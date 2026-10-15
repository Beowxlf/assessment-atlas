"""Single-operator workspace with opt-in authenticated HTTPS proxy hosting."""
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
from .vulnerability_tools import VulnerabilityTools
from .hosted_auth import HostedAuth
from .terminal import Terminals

STATIC = Path(__file__).parent / "static"
ROOT = Path(__file__).parent.parent
MAX_REQUEST = 12 * 1024 * 1024


class AtlasServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store, hosted=None):
        if address[0]!='127.0.0.1':raise ImportProblem('Keep Atlas on loopback; use the configured HTTPS reverse proxy for browser hosting.')
        super().__init__(address, Handler)
        self.store = store
        self.session = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.web = WebTools(store,self.server_address[1])
        self.vulnerability = VulnerabilityTools(store)
        self.hosted=hosted
        self.terminals=Terminals(store)

    def server_close(self):
        self.terminals.shutdown()
        self.vulnerability.shutdown()
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
            self.send_header("Set-Cookie", cookie if isinstance(cookie,str) else f"atlas_session={self.server.session}; Path=/; HttpOnly; SameSite=Strict")
        if self.server.hosted:self.send_header('Strict-Transport-Security','max-age=31536000')
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        try:
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            # A closed browser must not turn an already completed operation into
            # a traceback/retry or place request details in terminal logs.
            self.close_connection=True

    def trusted_host(self):
        if len(self.headers.get_all('Host',[]))!=1:return False
        if self.server.hosted:return len(self.headers.get_all('X-Forwarded-Proto',[]))==1 and self.server.hosted.trusted(self.headers,self.client_address[0])
        port = self.server.server_address[1]
        return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def authenticated(self):
        if self.server.hosted:
            self.operator_session=self.server.hosted.session(self.headers.get('Cookie',''))
            return self.operator_session is not None
        cookies = {part.strip() for part in self.headers.get("Cookie", "").split(";")}
        return "atlas_session=" + self.server.session in cookies

    def owner(self):return self.operator_session['id'] if self.server.hosted else self.server.session
    def csrf(self):return self.operator_session['nonce'] if self.server.hosted else self.server.nonce

    def do_GET(self):
        if not self.trusted_host():
            return self.respond({"error": "Unrecognized local host."}, 403)
        path = urlsplit(self.path).path
        if self.server.hosted and not self.authenticated():
            files={'/':('login.html','text/html'),'/login.js':('login.js','text/javascript'),'/styles.css':('styles.css','text/css')}
            if path in files:
                name,mime=files[path];return self.respond((STATIC/name).read_bytes(),mime=mime)
            return self.respond({'error':'Sign in to Assessment Atlas.'},401)
        if path in ('/operator-console.js','/operator-console.html','/vendor/xterm.js','/vendor/xterm.css'):
            return self.respond((STATIC/path[1:]).read_bytes(),mime='text/javascript' if path.endswith('.js') else 'text/css' if path.endswith('.css') else 'text/html')
        if path in ('/vulnerability-tools.js', '/vulnerability-tools.html', '/operator-tools.js'):
            return self.respond((STATIC / path[1:]).read_bytes(), mime='text/javascript' if path.endswith('.js') else 'text/html')
        if path in ('/investigations.js', '/investigations.html'):
            return self.respond((STATIC / path[1:]).read_bytes(), mime='text/javascript' if path.endswith('.js') else 'text/html')
        if path in ("/", "/app.js", "/web-tools.js", "/web-tools.html", "/styles.css"):
            file = STATIC / {"/": "index.html", "/app.js": "app.js", "/web-tools.js":"web-tools.js", "/web-tools.html":"web-tools.html", "/styles.css": "styles.css"}[path]
            mime = {"/": "text/html", "/app.js": "text/javascript", "/web-tools.js":"text/javascript", "/web-tools.html":"text/html", "/styles.css": "text/css"}[path]
            return self.respond(file.read_bytes(), mime=mime, cookie=path == "/" and not self.server.hosted)
        if not self.authenticated():
            return self.respond({"error": "Open the local application first."}, 403)
        try:
            if path=='/api/terminal/status':
                query=parse_qs(urlsplit(self.path).query);workspace=query.get('workspace',[''])[0];self.server.store.get(workspace)
                key=query.get('id',[''])[0]
                if key:return self.respond(self.server.terminals.get(workspace,self.owner(),key).status(int(query.get('cursor',['0'])[0])))
                return self.respond({'capabilities':self.server.terminals.capabilities(),'sessions':[s.status() for s in list(self.server.terminals.sessions.values()) if s.workspace==workspace and s.owner==self.owner()]})
            if path == '/api/vulnerability/status':
                query = parse_qs(urlsplit(self.path).query)
                return self.respond(self.server.vulnerability.status(query.get('workspace', [''])[0]))
            if path in ('/api/web/status','/api/web/ca'):
                query=parse_qs(urlsplit(self.path).query);workspace=query.get('workspace',[''])[0]
                self.server.store.get(workspace)
                proxies=[p for p in self.server.web.proxies.values() if p.workspace==workspace]
                if path=='/api/web/ca':
                    proxy=next((p for p in proxies if p.run['id']==query.get('id',[''])[0]),None)
                    if not proxy:raise ImportProblem('Proxy not found in this workspace.')
                    return self.respond(proxy.certificates.pem,mime='application/x-pem-file',attachment='atlas-isolated-proxy-ca.pem')
                from .web_protocols import available
                return self.respond({'runs':self.server.store.web_runs(workspace),'proxies':[p.status() for p in proxies],'browsers':[b.status() for b in self.server.web.browsers.values() if b.workspace==workspace],'sessions':self.server.web.session_list(workspace),'sockets':[s.status() for s in self.server.web.sockets.values() if s.workspace==workspace],'receivers':[r.status() for r in self.server.web.receivers.values() if r.workspace==workspace],'protocols':available()})
            if path == "/api/session":
                return self.respond({"nonce": self.csrf(), "version": __version__, "mode":'hosted' if self.server.hosted else 'local', "storage": 'Protected data on the Atlas server' if self.server.hosted else str(self.server.store.path), "vantage":'Terminal and native browser/web requests execute on the Atlas host. The accessing browser does not supply its VPN route.', "limits": "8 MiB per import; 10,000 entities / 50,000 observations per workspace"})
            if path == "/api/workspaces":
                return self.respond(self.server.store.list())
            if path == "/api/workspace":
                query = parse_qs(urlsplit(self.path).query)
                return self.respond(Store.view(self.server.store.get(query.get("id", [""])[0])))
            return self.respond({"error": "Not found."}, 404)
        except (ImportProblem,ValueError,TypeError) as exc:
            self.respond({"error": str(exc)}, 400)

    def do_POST(self):
        port = self.server.server_address[1]
        path=urlsplit(self.path).path
        allowed_origin = (self.server.hosted.origin,) if self.server.hosted else (f"http://127.0.0.1:{port}", f"http://localhost:{port}")
        if self.server.hosted and path=='/api/login':
            if not self.trusted_host() or self.headers.get('Origin') not in allowed_origin:return self.respond({'error':'Sign-in origin check failed.'},403)
            try:
                data=self.read_json(4096);result=self.server.hosted.login(data.get('password'))
                if not result:return self.respond({'error':'Operator sign-in failed.'},401)
                return self.respond({'signed_in':True},cookie=self.server.hosted.cookie(result[0]))
            except (ImportProblem,ValueError,UnicodeError,TypeError,socket.timeout) as exc:return self.respond({'error':str(exc)[:300]},400)
        if not self.trusted_host() or not self.authenticated() or self.headers.get("X-Atlas-Nonce") != self.csrf() or self.headers.get("Origin") not in allowed_origin:
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
            data=self.read_json()
            store = self.server.store
            workspace = data.get("workspace", "")
            if path.startswith('/api/investigation/'):
                if not isinstance(workspace, str):
                    raise ImportProblem('Choose a workspace identifier.')
                actions = {
                    '/api/investigation/save': store.save_investigation,
                    '/api/investigation/run': store.link_investigation_run,
                    '/api/investigation/evidence': store.link_investigation_evidence,
                    '/api/investigation/finding': store.investigation_finding,
                    '/api/investigation/next': store.investigation_next,
                }
                action = actions.get(path)
                if not action:
                    return self.respond({'error': 'Unknown investigation action.'}, 404)
                return self.respond(action(workspace, data))
            if path=='/api/logout' and self.server.hosted:
                owner=self.owner();self.server.terminals.close_owner(owner)
                for browser in list(self.server.web.browsers.values()):
                    if getattr(browser,'owner',None)==owner:browser.stop()
                self.server.hosted.logout(self.headers.get('Cookie',''))
                return self.respond({'signed_out':True},cookie=self.server.hosted.cookie(expire=True))
            if path.startswith('/api/terminal/'):
                self.server.store.get(workspace);terminals=self.server.terminals
                if path=='/api/terminal/preview':return self.respond(terminals.preview(data))
                if path=='/api/terminal/start':return self.respond(terminals.start(workspace,self.owner(),data))
                terminal=terminals.get(workspace,self.owner(),data.get('id'))
                if path=='/api/terminal/input':terminal.input(data.get('input'));return self.respond({'accepted':True})
                if path=='/api/terminal/resize':terminal.resize(data.get('rows'),data.get('cols'));return self.respond({'resized':True})
                if path=='/api/terminal/stop':terminal.stop();return self.respond(terminal.status())
                return self.respond({'error':'Unknown terminal action.'},404)
            if path=='/api/capture-selection':
                context=None
                if data.get('native_id'):
                    if data.get('source')=='terminal-selection':
                        terminal=self.server.terminals.get(workspace,self.owner(),data['native_id']);context={'run_id':terminal.id,'vantage':'Atlas Linux server','route':terminal.route}
                    elif data.get('source')=='browser-selection':
                        browser=self.server.web.browsers.get(data['native_id'])
                        if not browser or browser.workspace!=workspace or getattr(browser,'owner',None)!=self.owner():raise ImportProblem('Browser evidence belongs to another workspace/operator session.')
                        context=getattr(browser,'evidence_context',None)
                    else:raise ImportProblem('Unknown native evidence source.')
                return self.respond(store.capture_selection(workspace,data,context))
            if path.startswith('/api/vulnerability/'):
                if not isinstance(workspace, str):
                    raise ImportProblem('Choose a workspace identifier.')
                w = store.get(workspace); tools = self.server.vulnerability
                if path in ('/api/vulnerability/start', '/api/vulnerability/refresh'):
                    return self.respond(tools.start(workspace, data.get('config', {}), refresh=path.endswith('/refresh')))
                if path == '/api/vulnerability/stop':
                    return self.respond(tools.stop(workspace, data.get('id')))
                if path in ('/api/vulnerability/cache/import', '/api/vulnerability/cache/clear'):
                    with tools.lock:
                        if tools.active():
                            raise ImportProblem('Finish or stop the vulnerability job before changing its public cache.')
                        if path.endswith('/clear'):
                            tools.cache.clear(); return self.respond({'cleared': True, 'limit': 'Copied assessment evidence is retained.'})
                        return self.respond(tools.cache.ingest(data.get('provider'), data.get('content'), data.get('filename', 'public-feed.json')))
                if path == '/api/vulnerability/sbom':
                    from .vulnerability_match import sbom_inventory, validate_inventory
                    if not isinstance(data.get('subject'), str) or data['subject'] not in {e['id'] for e in w['entities']}:
                        raise ImportProblem('Select an existing asset for this SBOM.')
                    result = sbom_inventory(data.get('content'), data['subject'])
                    if result['inventory']:
                        result['inventory'] = validate_inventory(result['inventory'], w)
                    return self.respond(result)
                if path == '/api/vulnerability/inventory':
                    from .vulnerability_match import validate_inventory
                    return self.respond({'inventory': validate_inventory(data.get('inventory'), w)})
                return self.respond({'error': 'Unknown vulnerability action.'}, 404)
            if path.startswith('/api/web/'):
                store.get(workspace);tools=self.server.web;config=data.get('config',{})
                if not isinstance(config,dict):raise ImportProblem('Tool configuration must be an object.')
                if path=='/api/web/start':return self.respond(tools.start(workspace,data.get('kind'),config))
                if path=='/api/web/stop':return self.respond(tools.stop(workspace,data.get('id')))
                if path=='/api/web/request':return self.respond(tools.send(workspace,config))
                if path=='/api/web/compare':return self.respond(tools.compare(workspace,data.get('left'),data.get('right')))
                if path=='/api/web/ws/start':
                    from .web_socket import WebSocketSession
                    if sum(not s.closed for s in tools.sockets.values())>=4:raise ImportProblem('At most four live WebSocket sessions.')
                    session=WebSocketSession(tools,workspace,config);tools.sockets[session.run['id']]=session;return self.respond(session.status())
                if path in ('/api/web/ws/send','/api/web/ws/stop','/api/web/ws/finding'):
                    session=tools.sockets.get(data.get('id'))
                    if not session or session.workspace!=workspace:raise ImportProblem('WebSocket not found in this workspace.')
                    if path.endswith('/send'):return self.respond(session.send(data.get('message'),data.get('binary') is True))
                    if path.endswith('/finding'):return self.respond(session.finding(data.get('message_id'),data.get('title'),data.get('severity'),data.get('detail')))
                    session.close();return self.respond(session.status())
                if path=='/api/web/oob/start':
                    from .web_oob import OOBReceiver
                    if any(not r.closed for r in tools.receivers.values()):raise ImportProblem('Stop the current interaction receiver first.')
                    receiver=OOBReceiver(tools,workspace,config);tools.receivers[receiver.run['id']]=receiver;return self.respond(receiver.status())
                if path in ('/api/web/oob/issue','/api/web/oob/stop'):
                    receiver=tools.receivers.get(data.get('id'))
                    if not receiver or receiver.workspace!=workspace:raise ImportProblem('Interaction receiver not found in this workspace.')
                    if path.endswith('/issue'):
                        from .web_transport import Scope
                        scope=Scope(config,tools.port);tools.block_controls(scope);target=config.get('request_url') or config.get('url');scope.check(target)
                        return self.respond(receiver.allocate(target,str(data.get('parameter',''))[:200]))
                    receiver.close();return self.respond(receiver.status())
                if path=='/api/web/utility':
                    from .web_advanced import transform,token_measurements
                    if data.get('operation')=='tokens':return self.respond(token_measurements(data.get('samples')))
                    return self.respond({'result':transform(data.get('text'),data.get('operation')),'retention':'Transient utility; nothing saved or executed.'})
                if path=='/api/web/schema':
                    from .web_advanced import api_inventory
                    from .web_transport import Scope
                    return self.respond(api_inventory(data.get('schema'),Scope(config,self.server.server_address[1],resolve=False)))
                if path=='/api/web/session/save':return self.respond(tools.save_session(workspace,config))
                if path=='/api/web/session/forget':return self.respond(tools.forget_session(workspace,data.get('id')))
                if path=='/api/web/browser/session':
                    browser=tools.browsers.get(data.get('id'))
                    if not browser or browser.workspace!=workspace:raise ImportProblem('Active browser not found in this workspace.')
                    if self.server.hosted and getattr(browser,'owner',None)!=self.owner():raise ImportProblem('Browser belongs to another operator session.')
                    cookies=browser.snapshot()
                    from .web_evidence import web_url
                    settings=config.get('auth',{});origins=settings.get('origins',[web_url(config.get('url',''))[0]])
                    config={**config,'auth':{k:v for k,v in settings.items() if k in ('origins','check_url','success_text','success_status')}}
                    config['auth']['cookies']=[c for c in cookies if c.get('origin') in origins]
                    return self.respond(tools.save_session(workspace,config))
                if path=='/api/web/browser/action':
                    browser=tools.browsers.get(data.get('id'))
                    if not browser or browser.workspace!=workspace or self.server.hosted and getattr(browser,'owner',None)!=self.owner():raise ImportProblem('Browser is outside this workspace/operator session.')
                    return self.respond(browser.action(data.get('action',{})))
                if path in ('/api/web/proxy/start','/api/web/browser/start'):
                    if any(not p.closed for p in tools.proxies.values()):raise ImportProblem('Stop the current Atlas proxy/browser before starting another.')
                    if path=='/api/web/proxy/start':
                        from .web_proxy import Proxy
                        proxy=Proxy(tools,workspace,config);tools.proxies[proxy.run['id']]=proxy
                        return self.respond(proxy.status(include_token=True))
                    from .browser_session import BrowserSession
                    browser=BrowserSession(tools,workspace,config);tools.browsers[browser.proxy.run['id']]=browser;tools.proxies[browser.proxy.run['id']]=browser.proxy
                    browser.owner=self.owner()
                    return self.respond(browser.status())
                if path.startswith('/api/web/proxy/') or path=='/api/web/browser/stop':
                    proxy=tools.proxies.get(data.get('id'))
                    if not proxy or proxy.workspace!=workspace:raise ImportProblem('Proxy not found in this workspace.')
                    browser=tools.browsers.get(proxy.run['id'])
                    if self.server.hosted and browser and getattr(browser,'owner',None)!=self.owner():raise ImportProblem('Browser belongs to another operator session.')
                    if path in ('/api/web/proxy/stop','/api/web/browser/stop'):
                        browser=tools.browsers.get(proxy.run['id'])
                        if browser:browser.stop()
                        else:proxy.close()
                    elif path=='/api/web/proxy/intercept':
                        if not isinstance(data.get('enabled'),bool):raise ImportProblem('Interception setting must be boolean.')
                        proxy.intercept=data['enabled']
                    elif path=='/api/web/proxy/intercept-response':
                        if not isinstance(data.get('enabled'),bool):raise ImportProblem('Interception setting must be boolean.')
                        proxy.intercept_response=data['enabled']
                    elif path=='/api/web/proxy/intercept-websocket':
                        if not isinstance(data.get('enabled'),bool):raise ImportProblem('Interception setting must be boolean.')
                        proxy.ws_intercept=data['enabled']
                    elif path=='/api/web/proxy/decide':proxy.decide(data.get('pending_id'),data.get('action'),data.get('changes',{}))
                    else:raise ImportProblem('Unknown proxy action.')
                    return self.respond(proxy.status())
                return self.respond({'error':'Unknown web tool action.'},404)
            if path == "/api/create":
                return self.respond(Store.view(store.create(data.get("name"), data.get("scope", ""))))
            if path == "/api/delete":
                if self.server.terminals.active(workspace):raise ImportProblem('Stop active terminals before deleting this workspace.')
                if self.server.vulnerability.active(workspace):
                    raise ImportProblem('Stop the vulnerability job before deleting this workspace.')
                if any(j['workspace']==workspace and j['thread'].is_alive() for j in self.server.web.jobs.values()) or any(p.workspace==workspace and not p.closed for p in self.server.web.proxies.values()) or any(s.workspace==workspace and not s.closed for s in self.server.web.sockets.values()) or any(r.workspace==workspace and not r.closed for r in self.server.web.receivers.values()):raise ImportProblem('Stop active web runs, browsers, WebSockets and interaction receivers before deleting this workspace.')
                self.server.terminals.delete_workspace(workspace, data.get("confirmation"))
                for row in self.server.web.session_list(workspace):self.server.web.forget_session(workspace,row['id'])
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

    def read_json(self,maximum=MAX_REQUEST):
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1:raise ImportProblem('Use one Content-Length and no transfer encoding.')
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ImportProblem('JSON request required.')
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<=maximum:self.close_connection=True;raise ImportProblem('Request too large or empty.')
        self.connection.settimeout(15);content=self.rfile.read(length)
        if len(content)!=length:raise ImportProblem('Incomplete JSON request.')
        data=parse_json(content.decode('utf-8'))
        if not isinstance(data,dict):raise ImportProblem('Request must be an object.')
        return data


def main():
    if sys.version_info < (3, 12):
        raise SystemExit("Assessment Atlas requires Python 3.12 or newer.")
    parser = argparse.ArgumentParser(description="Assessment Atlas local application")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument('--host',choices=['127.0.0.1'],default='127.0.0.1',help='Backend loopback address; use the HTTPS proxy for browser access.')
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "AssessmentAtlas")
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument('--public-url',help='Exact HTTPS origin behind the configured loopback proxy; requires a protected operator password hash.')
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
    hosted=HostedAuth(args.public_url,args.data_dir/'operator-auth.json') if args.public_url else None
    server = AtlasServer((args.host, args.port), Store(args.data_dir / "atlas.sqlite3"),hosted=hosted)
    url = hosted.origin if hosted else f"http://127.0.0.1:{server.server_address[1]}"
    print(f"Assessment Atlas {__version__}: {url}\nLocal storage: {server.store.path}\nPress Ctrl+C to close. Imports are inert; native web tools require deliberate target scope.", flush=True)
    if not args.no_open and not hosted:
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
