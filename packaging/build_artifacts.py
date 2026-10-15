"""Build the source/wheel and installer ZIP; never includes local evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("Choose an empty output folder to avoid mixing releases.")
    subprocess.run([sys.executable, "-m", "pip", "wheel", str(root), "--no-deps", "--no-build-isolation", "--wheel-dir", str(output)], check=True)
    # Build from the sdist once too: catches missing MANIFEST/source build inputs.
    command = "import setuptools.build_meta as b; b.build_sdist(" + repr(str(output)) + ")"
    subprocess.run([sys.executable, "-c", command], cwd=root, check=True)
    with tempfile.TemporaryDirectory(prefix="atlas-source-wheel-") as temporary:
        source = next(output.glob("*.tar.gz"))
        subprocess.run([sys.executable, "-m", "pip", "wheel", str(source), "--no-deps", "--no-build-isolation", "--wheel-dir", temporary], check=True)
        with zipfile.ZipFile(next(Path(temporary).glob("*.whl"))) as rebuilt, zipfile.ZipFile(next(output.glob("*.whl"))) as direct:
            # WHEEL/RECORD contain build details; all shipped runtime bytes agree.
            files = {n for n in direct.namelist() if n.startswith("atlas/")}
            if files != {n for n in rebuilt.namelist() if n.startswith("atlas/")} or any(direct.read(n) != rebuilt.read(n) for n in files):
                raise SystemExit("Source and direct wheel contain different runtime files.")
    installer = output / "assessment-atlas-installers.zip"
    with zipfile.ZipFile(installer, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ("install.py", "install-linux.sh", "install-windows.ps1", "assessment-atlas.svg"):
            archive.write(root / "packaging" / name, "packaging/" + name)
    files = sorted(p for p in output.iterdir() if p.is_file())
    checksums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (output / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in checksums.items()), encoding="utf-8")
    print(json.dumps({"artifacts": checksums, "runtime_byte_equality_from_sdist": True}, indent=2))


if __name__ == "__main__":
    main()
