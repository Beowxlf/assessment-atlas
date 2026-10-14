"""Create a source/runnable ZIP from an exact clean Git revision, no runtime bundles."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile


def git(*args):
    return subprocess.run(["git",*args],check=True,capture_output=True).stdout


def main():
    parser=argparse.ArgumentParser(description="Package a clean Assessment Atlas checkout. Requires Git; refuses existing output.")
    parser.add_argument("output",type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parent.parent
    if Path.cwd().resolve()!=root:
        raise SystemExit("Run this command from the repository root.")
    sys.path.insert(0,str(root))
    from atlas import __version__
    if git("status","--porcelain").strip():
        raise SystemExit("Commit or preserve changes first; the package must represent a clean revision.")
    revision=git("rev-parse","HEAD").decode().strip()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    # Exclusive creation avoids overwriting unrelated deliverables.
    with args.output.open("xb") as destination:
        archive=git("archive","--format=zip",revision)
        destination.write(archive)
    with zipfile.ZipFile(args.output,"a",compression=zipfile.ZIP_DEFLATED) as archive:
        entries={item.filename:hashlib.sha256(archive.read(item)).hexdigest() for item in archive.infolist() if not item.is_dir()}
        if any(name.endswith((".sqlite3",".pcap",".pem",".key")) or name.startswith(("work/","evidence/","data/",".git/")) for name in entries):
            raise SystemExit("Unexpected sensitive/intermediate file in tracked archive; preserve output for inspection.")
        manifest={"product":"Assessment Atlas","version":__version__,"source_revision":revision,
                  "repository":"https://github.com/Beowxlf/assessment-atlas","built_at":dt.datetime.now(dt.timezone.utc).isoformat(),
                  "requires":"Python 3.12+; HTTP/2: h2; HTTP/3: aioquic; WebSockets: wsproto (requirements-protocols.txt); TLS interception: cryptography; isolated browser: Node.js/Playwright with Edge on Windows or sandboxed Chromium on Linux; no runtime bundled", "files_sha256":entries,
                  "evidence":"All bundled fixtures are synthetic; no live engagement data or credentials included.",
                  "license":"Owner decision pending; no open-source license selected."}
        archive.writestr("PACKAGE_MANIFEST.json",json.dumps(manifest,indent=2))
    with zipfile.ZipFile(args.output) as archive:
        if archive.testzip():raise SystemExit("Archive integrity check failed.")
        manifest=json.loads(archive.read("PACKAGE_MANIFEST.json"))
        for name,digest in manifest["files_sha256"].items():
            if hashlib.sha256(archive.read(name)).hexdigest()!=digest:raise SystemExit("Package hash mismatch: "+name)
    print(json.dumps({"path":str(args.output.resolve()),"source_revision":revision,"sha256":hashlib.sha256(args.output.read_bytes()).hexdigest(),"verified_source_files":len(entries)}))


if __name__=="__main__":main()
