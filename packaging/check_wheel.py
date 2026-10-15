"""Exercise an isolated wheel install away from the source checkout.

Creates a disposable virtual environment, imports only synthetic fixtures and
contacts only its own loopback app. No live target or desktop display is used.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile

SMOKE = r'''
import http.cookiejar, importlib.metadata, json, pathlib, threading, urllib.request
import atlas
from atlas.server import AtlasServer
from atlas.store import Store
from atlas.importers import parse

root = pathlib.Path(atlas.__file__).parent
assert root.resolve().is_relative_to(pathlib.Path(__import__('sys').prefix).resolve()), root
for name in ('index.html', 'app.js', 'desktop-tools.js', 'styles.css', 'operator-console.html', 'investigations.js', 'web-tools.js', 'vendor/xterm.js', 'vendor/xterm-LICENSE.txt'):
    assert (root / 'static' / name).is_file(), name
assert (root / 'browser_session.cjs').is_file()
for name in ('nmap.xml', 'device.json', 'scan.nessus', 'nuclei.jsonl', 'httpx.jsonl', 'manual.json'):
    parsed = parse((root / 'demo_fixtures' / name).read_text(encoding='utf-8'))
    assert parsed.entities, name
assert 'assessment-atlas = atlas.desktop:main' in importlib.metadata.distribution('assessment-atlas').read_text('entry_points.txt')
assert not __import__('importlib').util.find_spec('webview'), 'core wheel unexpectedly installed GUI dependencies'
import atlas.desktop  # GUI must remain lazy so core-only browser mode can start.
import atlas.companion, atlas.lifecycle

server = AtlasServer(('127.0.0.1', 0), Store(pathlib.Path('data') / 'atlas.sqlite3'))
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
origin = 'http://127.0.0.1:' + str(server.server_address[1])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
try:
    assert b'Assessment Atlas' in opener.open(origin + '/', timeout=10).read()
    for name in ('/app.js', '/desktop-tools.js', '/operator-console.js', '/vendor/xterm.js', '/investigations.html'):
        assert len(opener.open(origin + name, timeout=10).read()) > 50, name
    session = json.load(opener.open(origin + '/api/session', timeout=10))
    companion = json.load(opener.open(origin + '/api/companion/status', timeout=10))
    assert companion['client_available'] and not companion['connected']
    request = urllib.request.Request(origin + '/api/demo', data=b'{}', headers={'Content-Type':'application/json', 'Origin':origin, 'X-Atlas-Nonce':session['nonce']})
    workspace = json.load(opener.open(request, timeout=10))
    saved = json.load(opener.open(origin + '/api/workspace?id=' + workspace['id'], timeout=10))
    assert len(saved['imports']) == 6 and saved['observations']
    print(json.dumps({'installed_version':atlas.__version__, 'synthetic_imports':len(saved['imports']), 'observations':len(saved['observations']), 'local_http_assets':True, 'isolated_install':True}))
finally:
    server.shutdown(); server.server_close(); thread.join(10)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith(("work/", "data/", "evidence/", "tests/", "secrets/")) or name.endswith((".sqlite3", ".pem", ".key", ".pcap")):
                raise SystemExit("Unexpected file in wheel: " + name)
    with tempfile.TemporaryDirectory(prefix="atlas-wheel-check-") as temporary:
        target = Path(temporary)
        environment = target / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], cwd=target, check=True)
        subprocess.run([str(python), "-I", "-c", SMOKE], cwd=target, check=True)
        subprocess.run([str(python), "-I", "-m", "atlas.desktop", "--help"], cwd=target, check=True)


if __name__ == "__main__":
    main()
