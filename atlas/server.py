"""Single-operator loopback application. Not a remote/multi-user web server."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
from urllib.parse import urlsplit, parse_qs
import webbrowser

from . import __version__
from .importers import ImportProblem, parse, parse_json, MAX_BYTES
from .store import Store, html_report
from .web_tools import WebTools

STATIC = Path(__file__).parent / "static"
ROOT = Path(__file__).parent.parent
MAX_REQUEST = 12 * 1024 * 1024


class AtlasServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        super().__init__(address, Handler)
        self.store = store
        self.session = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.web = WebTools(store,self.server_address[1])

    def server_close(self):
        self.web.shutdown()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "AssessmentAtlas/" + __version__
    def log_message(self, *_):
        pass  # Do not place filenames, targets or imported content in terminal logs.

    def respond(self, data, status=200, mime="application/json", cookie=False, attachment=None):
        if mime == "application/json":
            data = json.dumps(data, ensure_ascii=False).encode("utf-8")
        elif isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        if cookie:
            self.send_header("Set-Cookie", f"atlas_session={self.server.session}; Path=/; HttpOnly; SameSite=Strict")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(data)

    def trusted_host(self):
        port = self.server.server_address[1]
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def authenticated(self):
        cookies = {part.strip() for part in self.headers.get("Cookie", "").split(";")}
        return "atlas_session=" + self.server.session in cookies

    def do_GET(self):
        if not self.trusted_host():
            return self.respond({"error": "Unrecognized local host."}, 403)
        path = urlsplit(self.path).path
        if path in ("/", "/app.js", "/web-tools.js", "/web-tools.html", "/styles.css"):
            file = STATIC / {"/": "index.html", "/app.js": "app.js", "/web-tools.js":"web-tools.js", "/web-tools.html":"web-tools.html", "/styles.css": "styles.css"}[path]
            mime = {"/": "text/html", "/app.js": "text/javascript", "/web-tools.js":"text/javascript", "/web-tools.html":"text/html", "/styles.css": "text/css"}[path]
            return self.respond(file.read_bytes(), mime=mime, cookie=path == "/")
        if not self.authenticated():
            return self.respond({"error": "Open the local application first."}, 403)
        try:
            if path in ('/api/web/status','/api/web/ca'):
                query=parse_qs(urlsplit(self.path).query);workspace=query.get('workspace',[''])[0]
                self.server.store.get(workspace)
                proxies=[p for p in self.server.web.proxies.values() if p.workspace==workspace]
                if path=='/api/web/ca':
                    proxy=next((p for p in proxies if p.run['id']==query.get('id',[''])[0]),None)
                    if not proxy:raise ImportProblem('Proxy not found in this workspace.')
                    return self.respond(proxy.certificates.pem,mime='application/x-pem-file',attachment='atlas-isolated-proxy-ca.pem')
                return self.respond({'runs':self.server.store.web_runs(workspace),'proxies':[p.status() for p in proxies],'browsers':[b.status() for b in self.server.web.browsers.values() if b.workspace==workspace]})
            if path == "/api/session":
                return self.respond({"nonce": self.server.nonce, "version": __version__, "storage": str(self.server.store.path), "limits": "8 MiB per import; 10,000 entities / 50,000 observations per workspace"})
            if path == "/api/workspaces":
                return self.respond(self.server.store.list())
            if path == "/api/workspace":
                query = parse_qs(urlsplit(self.path).query)
                return self.respond(Store.view(self.server.store.get(query.get("id", [""])[0])))
            return self.respond({"error": "Not found."}, 404)
        except ImportProblem as exc:
            self.respond({"error": str(exc)}, 400)

    def do_POST(self):
        port = self.server.server_address[1]
        allowed_origin = (f"http://127.0.0.1:{port}", f"http://localhost:{port}")
        if not self.trusted_host() or not self.authenticated() or self.headers.get("X-Atlas-Nonce") != self.server.nonce or self.headers.get("Origin") not in allowed_origin:
            # Drain small rejected bodies before closing so Windows clients can
            # reliably receive the 403 instead of an unread-body connection reset.
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= 65536:
                    self.connection.settimeout(1)
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
            self.close_connection = True
            return self.respond({"error": "Local session check failed."}, 403)
        try:
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise ImportProblem("JSON request required.")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_REQUEST:
                return self.respond({"error": "Request too large or empty."}, 413)
            self.connection.settimeout(15)
            data = parse_json(self.rfile.read(length).decode("utf-8"))
            if not isinstance(data, dict):
                raise ImportProblem("Request must be an object.")
            path = urlsplit(self.path).path
            store = self.server.store
            workspace = data.get("workspace", "")
            if path.startswith('/api/web/'):
                store.get(workspace);tools=self.server.web;config=data.get('config',{})
                if not isinstance(config,dict):raise ImportProblem('Tool configuration must be an object.')
                if path=='/api/web/start':return self.respond(tools.start(workspace,data.get('kind'),config))
                if path=='/api/web/stop':return self.respond(tools.stop(workspace,data.get('id')))
                if path=='/api/web/request':return self.respond(tools.send(workspace,config))
                if path=='/api/web/compare':return self.respond(tools.compare(workspace,data.get('left'),data.get('right')))
                if path in ('/api/web/proxy/start','/api/web/browser/start'):
                    if any(not p.closed for p in tools.proxies.values()):raise ImportProblem('Stop the current Atlas proxy/browser before starting another.')
                    if path=='/api/web/proxy/start':
                        from .web_proxy import Proxy
                        proxy=Proxy(tools,workspace,config);tools.proxies[proxy.run['id']]=proxy
                        return self.respond(proxy.status(include_token=True))
                    from .browser_session import BrowserSession
                    browser=BrowserSession(tools,workspace,config);tools.browsers[browser.proxy.run['id']]=browser;tools.proxies[browser.proxy.run['id']]=browser.proxy
                    return self.respond(browser.status())
                if path.startswith('/api/web/proxy/') or path=='/api/web/browser/stop':
                    proxy=tools.proxies.get(data.get('id'))
                    if not proxy or proxy.workspace!=workspace:raise ImportProblem('Proxy not found in this workspace.')
                    if path in ('/api/web/proxy/stop','/api/web/browser/stop'):
                        browser=tools.browsers.get(proxy.run['id'])
                        if browser:browser.stop()
                        else:proxy.close()
                    elif path=='/api/web/proxy/intercept':
                        if not isinstance(data.get('enabled'),bool):raise ImportProblem('Interception setting must be boolean.')
                        proxy.intercept=data['enabled']
                    elif path=='/api/web/proxy/decide':proxy.decide(data.get('pending_id'),data.get('action'),data.get('changes',{}))
                    else:raise ImportProblem('Unknown proxy action.')
                    return self.respond(proxy.status())
                return self.respond({'error':'Unknown web tool action.'},404)
            if path == "/api/create":
                return self.respond(Store.view(store.create(data.get("name"), data.get("scope", ""))))
            if path == "/api/delete":
                if any(j['workspace']==workspace and j['thread'].is_alive() for j in self.server.web.jobs.values()) or any(p.workspace==workspace and not p.closed for p in self.server.web.proxies.values()):raise ImportProblem('Stop active web runs, browsers and proxies before deleting this workspace.')
                store.delete(workspace, data.get("confirmation"))
                return self.respond({"deleted": True})
            if path in ("/api/preview", "/api/import"):
                context = data.get("context", {})
                if not isinstance(context, dict):
                    raise ImportProblem("Import metadata must be an object.")
                if any(not isinstance(v, str) or len(v) > 500 for v in context.values()):
                    raise ImportProblem("Import metadata must be short text.")
                if path == "/api/preview":
                    b = parse(data.get("content"), data.get("source", "auto"), context)
                    return self.respond({"source": b.source, "entities": len(b.entities), "observations": len(b.observations), "findings": len(b.findings), "warnings": b.warnings, "sample": b.entities[:8]})
                return self.respond(store.import_file(workspace, data.get("content"), data.get("filename", "import"), data.get("source", "auto"), context))
            if path == "/api/reconcile":
                return self.respond(store.reconcile(workspace, data.get("left"), data.get("right"), data.get("reason")))
            if path == "/api/undo":
                return self.respond(store.undo(workspace, data.get("decision")))
            if path == "/api/record":
                return self.respond(store.record(workspace, data))
            if path == "/api/review":
                return self.respond(store.update_record(workspace, data))
            if path == "/api/export":
                w = store.export(workspace, data.get("identifiers") is True, str(data.get("kind", "")), str(data.get("claim", "")), str(data.get("import_id", "")))
                if data.get("format") == "html":
                    return self.respond(html_report(w), mime="text/html", attachment="assessment-report.html")
                return self.respond(w)
            if path == "/api/demo":
                w = store.create("Synthetic training engagement", "Synthetic documentation-only addresses and findings. Not a live assessment.")
                for filename in ("nmap.xml", "device.json", "scan.nessus", "nuclei.jsonl", "httpx.jsonl", "manual.json"):
                    store.import_file(w["id"], (ROOT / "fixtures" / filename).read_text(encoding="utf-8"), filename, "auto", {"vantage": "Synthetic assessor", "namespace": "synthetic"})
                return self.respond(Store.view(store.get(w["id"])))
            return self.respond({"error": "Not found."}, 404)
        except (ImportProblem, UnicodeError, ValueError, TypeError, socket.timeout) as exc:
            self.respond({"error": str(exc)[:400]}, 400)
        except Exception:
            self.respond({"error": "The operation failed. Existing saved data remains available; restart the local application if necessary."}, 500)


def main():
    if sys.version_info < (3, 12):
        raise SystemExit("Assessment Atlas requires Python 3.12 or newer.")
    parser = argparse.ArgumentParser(description="Assessment Atlas local application")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "AssessmentAtlas")
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args()
    args.data_dir.mkdir(parents=True, exist_ok=True)
    guard = (args.data_dir / "instance.lock").open("a+b")
    guard.seek(0)
    guard.write(b"0")
    guard.flush()
    guard.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(guard.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        guard.close()
        raise SystemExit("This data folder is already open in another Assessment Atlas process. Use that instance or a separate --data-dir.")
    server = AtlasServer(("127.0.0.1", args.port), Store(args.data_dir / "atlas.sqlite3"))
    url = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Assessment Atlas {__version__}: {url}\nLocal storage: {server.store.path}\nPress Ctrl+C to close. Imports are inert; native web tools require deliberate target scope.", flush=True)
    if not args.no_open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        guard.close()


if __name__ == "__main__":
    main()
