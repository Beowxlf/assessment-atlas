"""Install a reviewed local source tree or wheel into a per-user environment.

No service, VPN, proxy, trust store, administrator permission or startup task is
configured. Dependencies are fetched by pip only when this installer is run.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import venv

MARKER = "assessment-atlas-install.json"


def validate_system_qt():
    """An explicit distro-Qt install must have a complete Qt 6 WebEngine.

    Probe in a separate interpreter: selecting a binding must not contaminate
    the installer's process, and importing the module needs no display.
    """
    probe = (
        "import importlib, json, os\n"
        "for binding in ('PySide6', 'PyQt6'):\n"
        " try:\n"
        "  root = importlib.import_module(binding)\n"
        "  importlib.import_module(binding + '.QtWebEngineWidgets')\n"
        "  importlib.import_module(binding + '.QtWebChannel')\n"
        "  core = importlib.import_module(binding + '.QtCore')\n"
        "  importlib.import_module(binding + '.QtNetwork')\n"
        "  os.environ['QT_API'] = binding.lower()\n"
        "  importlib.import_module('qtpy.QtWebEngineWidgets')\n"
        "  print(json.dumps({'binding': binding, 'version': getattr(root, '__version__', getattr(core, 'PYQT_VERSION_STR', 'distribution package')), 'qt_version': core.qVersion()}))\n"
        "  break\n"
        " except ImportError:\n"
        "  continue\n"
        "else:\n"
        " raise SystemExit('System Qt 6 WebEngine and QtPy are unavailable. Use the default installer, or install your distribution Qt 6 WebEngine and QtPy packages first.')\n"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ValueError("System Qt 6 WebEngine and QtPy are unavailable. Use the default installer, or install your distribution Qt 6 WebEngine and QtPy packages first.")
    return json.loads(result.stdout)


def default_prefix():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "AssessmentAtlasRuntime"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "assessment-atlas-runtime"


def desktop_entry(executable, icon, browser=False):
    # Desktop Entry Exec has its own quoting rules, independent of shell syntax.
    value = str(executable)
    for before, after in (("\\", "\\\\\\\\"), ('"', '\\\\"'), ("`", "\\\\`"), ("$", "\\\\$"), ("%", "%%")):
        value = value.replace(before, after)
    arguments = " --browser" if browser else ""
    terminal = "true" if browser else "false"
    icon = str(icon).replace("\\", "\\\\")
    return ("[Desktop Entry]\nType=Application\nName=Assessment Atlas\n"
            "Comment=Local assessment workspace using this host's network routes\n"
            f'Exec="{value}"{arguments}\nIcon={icon}\nTerminal={terminal}\nCategories=Network;Security;\n')


def write_shortcut(prefix, executable, browser=False):
    if os.name == "nt":
        menu = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        menu.mkdir(parents=True, exist_ok=True)
        shortcut = menu / "Assessment Atlas.lnk"
        # A fixed script and explicit environment values avoid interpreting paths
        # as PowerShell source, including usernames containing quotes or '$'.
        environment = dict(os.environ, ATLAS_SHORTCUT=str(shortcut), ATLAS_EXECUTABLE=str(executable), ATLAS_WORKDIR=str(prefix), ATLAS_ARGUMENTS="--browser" if browser else "")
        command = ("$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:ATLAS_SHORTCUT);"
                   "$s.TargetPath=$env:ATLAS_EXECUTABLE;$s.WorkingDirectory=$env:ATLAS_WORKDIR;$s.Arguments=$env:ATLAS_ARGUMENTS;"
                   "$s.Description='Assessment Atlas local assessment workspace';$s.Save()")
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command], env=environment, check=True)
        return shortcut
    if sys.platform.startswith("linux"):
        menu = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "applications"
        menu.mkdir(parents=True, exist_ok=True)
        icon = prefix / "assessment-atlas.svg"
        shutil.copyfile(Path(__file__).with_name("assessment-atlas.svg"), icon)
        shortcut = menu / "assessment-atlas.desktop"
        shortcut.write_text(desktop_entry(executable, icon, browser), encoding="utf-8")
        shortcut.chmod(0o644)
        return shortcut
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="Reviewed local source directory or wheel; no remote URL is accepted.")
    parser.add_argument("--prefix", type=Path, default=default_prefix())
    parser.add_argument("--core-only", action="store_true", help="Install local browser/CLI mode without optional native/protocol engines.")
    parser.add_argument("--system-qt", action="store_true", help="Linux only: explicitly reuse the current Python's installed Qt 6 WebEngine and QtPy instead of downloading the pinned engine.")
    parser.add_argument("--no-shortcut", action="store_true")
    args = parser.parse_args()
    if sys.version_info < (3, 12):
        parser.error("Python 3.12 or newer is required. On Debian-family systems install python3-venv too.")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parser.error("Run the installer as your regular desktop user, without sudo.")
    qt = None
    if args.system_qt:
        if not sys.platform.startswith("linux") or args.core_only:
            parser.error("--system-qt requires a native Linux installation and cannot be combined with --core-only.")
        try:
            qt = validate_system_qt()
        except (ValueError, OSError, subprocess.SubprocessError):
            parser.error("System Qt 6 WebEngine and QtPy are unavailable. Use the default installer, or install your distribution Qt 6 WebEngine and QtPy packages first.")
    source = args.source.expanduser().resolve()
    if not ((source.is_dir() and (source / "pyproject.toml").is_file()) or (source.is_file() and source.suffix == ".whl")):
        parser.error("--source must be a reviewed local source tree or .whl file.")
    prefix = args.prefix.expanduser().resolve()
    if any(ord(char) < 32 for char in str(prefix)) or (sys.platform.startswith("linux") and "=" in str(prefix)):
        parser.error("The install path cannot contain control characters or a Linux desktop Exec '=' character.")
    marker = prefix / MARKER
    if prefix.exists() and not marker.is_file() and any(prefix.iterdir()):
        parser.error("The destination contains unrelated files. Choose an empty directory or an existing Atlas runtime install.")
    if marker.is_file():
        try:
            installed = json.loads(marker.read_text(encoding="utf-8"))
            if installed.get("product") != "Assessment Atlas":
                raise ValueError()
        except (ValueError, OSError):
            parser.error("The destination does not have a valid Atlas install marker.")
        if bool(installed.get("system_qt")) != args.system_qt:
            parser.error("This runtime uses a different Qt dependency profile. Keep its existing --system-qt choice when updating, or choose a new --prefix.")
    prefix.mkdir(parents=True, exist_ok=True)
    # Mark before creating the venv so a failed dependency download can be retried.
    marker.write_text(json.dumps({"product": "Assessment Atlas", "runtime_only": True,
                                 "python": platform.python_version(), "system_qt": qt}, indent=2) + "\n", encoding="utf-8")
    environment = prefix / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=args.system_qt).create(environment)
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    extras = "" if args.core_only else ("[desktop,protocols,web]" if args.system_qt or os.name == "nt" or sys.platform == "darwin" else "[desktop-qt,protocols,web]")
    subprocess.run([str(python), "-m", "pip", "install", "--upgrade", str(source) + extras], check=True)
    command = "atlas-desktop" if args.core_only else "assessment-atlas"
    executable = scripts / (command + ".exe" if os.name == "nt" else command)
    shortcut = None if args.no_shortcut else write_shortcut(prefix, executable, browser=args.core_only)
    print("Assessment Atlas installed for this user.")
    if qt:
        print("Native engine: explicitly reused system " + qt["binding"] + " " + qt["version"] + ". Distribution updates manage this engine.")
    print("Launch: " + str(executable) + (" --browser" if args.core_only else ""))
    if args.core_only:
        print("Core-only mode: launch with --browser, or install the desktop extras later.")
    if shortcut:
        print("Application menu shortcut: " + str(shortcut))
    print("Saved assessments use the separate app data folder and are not changed by runtime updates.")
    print("Connect your VPN on this host, then review the target's actual route inside Atlas before a test.")


if __name__ == "__main__":
    main()
