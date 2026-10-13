import base64
import copy
from http.client import HTTPConnection,HTTPSConnection
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit,parse_qs

from atlas.importers import ImportProblem,parse
from atlas.store import Store
from atlas.web_transport import Scope,fetch,request_headers
from atlas.web_tools import WebTools,passive_checks
from atlas.web_proxy import Proxy,LocalCertificates
from atlas.server import AtlasServer

TEMP=Path(__file__).resolve().parent.parent/'work/test-temp';TEMP.mkdir(parents=True,exist_ok=True)


class Fixture(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        self.server.seen.append(self.path);path=urlsplit(self.path).path
        status=200;extra=[]
        if path=='/':body='<a href="/page?q=alpha&token=synthetic-query-secret">Page</a><a href="/out">Redirect</a><a href="/logout">Logout</a><form action="/login"><input name="username"><input name="password"></form>'
        elif path=='/out':status=302;extra=[('Location',self.server.outside)];body=''
        elif path=='/echo':body='echo '+parse_qs(urlsplit(self.path).query).get('q',['baseline'])[0]
        elif path=='/status':status=403 if parse_qs(urlsplit(self.path).query).get('q',[''])[0]=='MAKE403' else 200;body='constant synthetic body'
        elif path=='/error':body='Traceback (most recent call last): synthetic error'
        elif path=='/auto-login':
            body='<script>fetch("/session",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:"synthetic",password:"fixture-only"})}).then(()=>fetch("/api/private",{credentials:"include"})).then(r=>r.text()).then(t=>document.body.dataset.loaded=t)</script>'
        elif path=='/api/private':
            status=200 if 'synthetic-browser-session' in self.headers.get('Cookie','') else 401;body='authenticated dynamic data' if status==200 else 'login required'
        elif path=='/large':body='A'*70000
        else:body='synthetic '+path
        raw=body.encode();self.send_response(status);self.send_header('Content-Type','text/html; charset=utf-8')
        for k,v in extra:self.send_header(k,v)
        self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        self.server.seen.append(self.path);raw=self.rfile.read(int(self.headers.get('Content-Length','0')));self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(raw)))
        if self.path=='/session':self.send_header('Set-Cookie','session=synthetic-browser-session; HttpOnly; Path=/')
        self.end_headers();self.wfile.write(raw)


def fixture_server():
    server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);server.seen=[];server.outside='http://127.0.0.1:1/outside';thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();return server


def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]


class NativeWebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEMP);self.store=Store(Path(self.temp.name)/'atlas.sqlite3');self.w=self.store.create('Native synthetic','Owned fixture only');self.tools=WebTools(self.store,8765);self.target=fixture_server();self.url=f'http://127.0.0.1:{self.target.server_address[1]}'
        self.config={'url':self.url+'/','authorized':True,'path_prefix':'/','vantage':'Synthetic test position','namespace':'test-web','max_requests':10,'max_seconds':10,'delay_ms':250,'max_depth':2,'exclude_paths':['/logout']}
    def tearDown(self):
        self.tools.shutdown();self.target.shutdown();self.target.server_close();self.temp.cleanup()
    def terminal(self,run):
        for _ in range(100):
            row=next(r for r in self.store.web_runs(self.w['id']) if r['id']==run['id'])
            if row['state'] not in ('queued','running'):return row
            time.sleep(.05)
        self.fail('Web run did not finish')
    def test_crawl_collects_parameters_and_blocks_exclusions_and_redirects(self):
        run=self.tools.start(self.w['id'],'crawl',self.config);result=self.terminal(run)
        self.assertEqual(result['state'],'completed');self.assertNotIn('/logout',self.target.seen);self.assertGreater(result['skipped'],0)
        w=self.store.get(self.w['id']);self.assertTrue(any(e['kind']=='web parameter' for e in w['entities']));self.assertTrue(any(o['kind']=='reported web link' and o['status']=='unknown' for o in w['observations']))
        self.assertTrue(all(o['collected_at'] and o['vantage']=='Synthetic test position' for o in w['observations']))
        self.assertNotIn('synthetic-query-secret',json.dumps(w));self.assertTrue(any(o['kind']=='HTTP response' for o in w['observations']))
    def test_request_limit_keeps_partial_result(self):
        result=self.terminal(self.tools.start(self.w['id'],'crawl',{**self.config,'max_requests':1}));self.assertEqual(result['state'],'partial');self.assertEqual(result['requests'],1);self.assertEqual(len(result['import_ids']),1)
    def test_cancellation_keeps_completed_evidence(self):
        run=self.tools.start(self.w['id'],'crawl',{**self.config,'paths':['/one','/two','/three'],'delay_ms':1000});time.sleep(.1);self.tools.stop(self.w['id'],run['id']);result=self.terminal(run)
        self.assertEqual(result['state'],'cancelled');self.assertGreaterEqual(result['requests'],1)
    def test_workbench_compare_and_sensitive_data_handling(self):
        first=self.tools.send(self.w['id'],{**self.config,'request_url':self.url+'/echo?q=alpha','headers':'Authorization: Bearer synthetic-auth-secret\nCookie: session=synthetic-cookie-secret','retain_body':True})
        second=self.tools.send(self.w['id'],{**self.config,'request_url':self.url+'/echo?q=beta','retain_body':True})
        comparison=self.tools.compare(self.w['id'],first['capture_id'],second['capture_id']);self.assertFalse(comparison['identical']);self.assertIn('alpha',comparison['diff']);self.assertIn('beta',comparison['diff'])
        saved=json.dumps(self.store.get(self.w['id']));self.assertNotIn('synthetic-auth-secret',saved);self.assertNotIn('synthetic-cookie-secret',saved)
        other=self.store.create('Other','fixture')
        with self.assertRaises(ImportProblem):self.tools.compare(other['id'],first['capture_id'],second['capture_id'])
    def test_parameter_payloads_have_baseline_and_reported_reflection(self):
        result=self.terminal(self.tools.start(self.w['id'],'payload',{**self.config,'request_url':self.url+'/echo?q=baseline','parameter':'q','payloads':['ATLAS_ONE','ATLAS_TWO']}))
        self.assertEqual(result['requests'],3);w=self.store.get(self.w['id']);self.assertEqual(len(w['findings']),2);self.assertTrue(all(f['validation']=='scanner-reported' for f in w['findings']))
    def test_explicit_scanner_checks_do_not_claim_exploitation(self):
        result=self.terminal(self.tools.start(self.w['id'],'scanner',self.config));self.assertEqual(result['requests'],1);w=self.store.get(self.w['id']);self.assertTrue(w['findings']);self.assertTrue(all('not validated' in f['description'] for f in w['findings']))
        capture_ids={o['value']['source_capture_id'] for o in w['observations'] if o['kind']=='HTTP transport observation'}
        self.assertEqual(len(capture_ids),1);self.assertTrue(all(i['intake_mode']=='native live' for i in w['imports']))
    def test_response_check_families_have_positive_and_negative_controls(self):
        event={'url':'https://owned.example/','response':{'headers':[{'name':'Content-Type','value':'TEXT/HTML'},{'name':'Set-Cookie','value':'session=synthetic'},{'name':'Access-Control-Allow-Origin','value':'*'},{'name':'Access-Control-Allow-Credentials','value':'true'}],'body':'Traceback (most recent call last):'}}
        expected={'atlas-csp','atlas-hsts','atlas-frame-policy','atlas-nosniff','atlas-cookie-httponly','atlas-cookie-secure','atlas-cors','atlas-error-signature'}
        self.assertEqual({issue['type'] for issue in passive_checks(event)},expected)
        event['response']['headers']=[{'name':k,'value':v} for k,v in [('Content-Type','text/html'),('Content-Security-Policy',"FRAME-ANCESTORS 'none'"),('Strict-Transport-Security','max-age=3600'),('X-Content-Type-Options','nosniff'),('Set-Cookie','session=synthetic; Secure; HttpOnly'),('Access-Control-Allow-Origin','https://owned.example')]];event['response']['body']='ordinary content'
        self.assertEqual(passive_checks(event),[])
    def test_parameter_status_difference_retains_baseline_evidence(self):
        result=self.terminal(self.tools.start(self.w['id'],'payload',{**self.config,'request_url':self.url+'/status?q=baseline','parameter':'q','payloads':['MAKE403']}))
        self.assertEqual(result['requests'],2);w=self.store.get(self.w['id']);self.assertTrue(any(f['external_id']=='atlas-status-difference' for f in w['findings']))
        observation=next(o for o in w['observations'] if o['kind']=='selected parameter test');self.assertTrue(observation['value']['baseline_response_sha256']);self.assertTrue(observation['value']['status_difference'])
    def test_scope_and_header_smuggling_guards(self):
        scope=Scope({**self.config,'path_prefix':'/app','url':self.url+'/app'})
        for url in (self.url+'/apple',self.url+'/app/%252e%252e/admin','http://127.0.0.1:1/app',self.url+'/app/%2f../x'):
            with self.subTest(url=url),self.assertRaises(ImportProblem):scope.check(url)
        for headers in ([{'name':'X-Bad','value':'one\r\nHost: evil'}],[{'name':'X-A','value':'one'},{'name':'x-a','value':'two'}]):
            with self.assertRaises(ImportProblem):request_headers(headers)
        with self.assertRaises(ImportProblem):Scope({**self.config,'authorized':False})
        with self.assertRaises(ImportProblem):Scope({**self.config,'url':'http://169.254.169.254/'})
        with self.assertRaises(ImportProblem):Scope({**self.config,'url':'http://127.0.0.1:8765/'},8765)
    def test_dns_is_pinned_after_scope_resolution(self):
        scope=Scope(self.config)
        with patch('socket.getaddrinfo',side_effect=AssertionError('Hostname was resolved again')):
            # create_connection uses numeric getaddrinfo too; inspect the bound address at its boundary.
            with patch('socket.create_connection',side_effect=lambda address,timeout: (_ for _ in ()).throw(OSError('synthetic stop'))) as connect:
                event=fetch(scope,self.url+'/')
        self.assertEqual(connect.call_args.args[0][0],'127.0.0.1');self.assertIn('error',event)
    def test_bounded_large_response_is_marked_truncated(self):
        event=fetch(Scope(self.config),self.url+'/large');self.assertTrue(event['response']['truncated']);self.assertEqual(event['response']['bytes'],65536)
    def test_web_envelope_is_inert_and_event_ids_are_idempotent(self):
        event={'id':'synthetic-stable','url':self.url+'/echo?q=secret','captured_at':'2026-10-13T02:00:00Z','request':{'method':'POST','headers':[{'name':'Content-Type','value':'application/json'}],'body':'{"password":"synthetic-json-secret","field":"value"}'},'response':{'status':200,'headers':[{'name':'Set-Cookie','value':'secret-cookie'}],'body':'token=synthetic-body-secret'}}
        event['response']['body']+='\nAuthorization: Bearer synthetic-inline-auth\nBearer synthetic-bearer-token'
        data={'format':'atlas-web/1','source':'web-proxy','tool_version':'synthetic','capture_mode':'redacted','events':[event]};content=json.dumps(data)
        with patch('socket.create_connection',side_effect=AssertionError('Import fetched URL')):bundle=parse(content,'auto')
        saved=json.dumps(bundle.observations);self.assertNotIn('synthetic-json-secret',saved);self.assertNotIn('secret-cookie',saved);self.assertNotIn('synthetic-body-secret',saved);self.assertNotIn('synthetic-inline-auth',saved);self.assertNotIn('synthetic-bearer-token',saved)
        one=self.store.import_file(self.w['id'],content,'web.json','auto',{});self.assertTrue(self.store.import_file(self.w['id'],content,'web.json','auto',{})['duplicate'])
        data['events'][0]['response']['status']=404
        with self.assertRaises(ImportProblem):self.store.import_file(self.w['id'],json.dumps(data),'web.json','auto',{})
        self.assertEqual(len(self.store.get(self.w['id'])['imports']),1)
    def test_proxy_requires_auth_and_intercept_can_edit_live_request(self):
        proxy=Proxy(self.tools,self.w['id'],{**self.config,'proxy_port':free_port(),'intercept':True});self.tools.proxies[proxy.run['id']]=proxy
        conn=HTTPConnection('127.0.0.1',proxy.server.server_address[1],timeout=5);conn.request('GET',self.url+'/echo?q=original');self.assertEqual(conn.getresponse().status,407);conn.close()
        result={}
        def send():
            conn=HTTPConnection('127.0.0.1',proxy.server.server_address[1],timeout=5);auth='Basic '+base64.b64encode(('atlas:'+proxy.token).encode()).decode();conn.request('GET',self.url+'/echo?q=original',headers={'Proxy-Authorization':auth});response=conn.getresponse();result['body']=response.read();result['status']=response.status;conn.close()
        thread=threading.Thread(target=send);thread.start()
        for _ in range(50):
            pending=proxy.status()['pending']
            if pending:break
            time.sleep(.02)
        self.assertTrue(pending);proxy.decide(pending[0]['id'],'forward',{'method':'POST','headers':[{'name':'Content-Type','value':'text/plain'}],'body':'edited synthetic body'});thread.join(5)
        self.assertEqual(result['status'],200);self.assertEqual(result['body'],b'edited synthetic body');self.assertTrue(any(o['kind']=='live request interception' for o in self.store.get(self.w['id'])['observations']))
        self.assertFalse(list(proxy.folder.glob('*.pem')))
        result.clear();thread=threading.Thread(target=send);thread.start()
        for _ in range(50):
            pending=proxy.status()['pending']
            if pending:break
            time.sleep(.02)
        before=len(self.target.seen);proxy.decide(pending[0]['id'],'drop',{});thread.join(5)
        self.assertEqual(result['status'],502);self.assertEqual(len(self.target.seen),before);self.assertTrue(any(o['kind']=='web request failure' for o in self.store.get(self.w['id'])['observations']))
    def test_https_interception_preserves_upstream_ca_checks(self):
        certificates=LocalCertificates();tls=fixture_server();tls.socket=certificates.context('127.0.0.1',Path(self.temp.name)).wrap_socket(tls.socket,server_side=True);tlsurl=f'https://127.0.0.1:{tls.server_address[1]}'
        try:
            config={**self.config,'url':tlsurl+'/','ca_pem':certificates.pem,'proxy_port':free_port()}
            proxy=Proxy(self.tools,self.w['id'],config);self.tools.proxies[proxy.run['id']]=proxy
            context=ssl.create_default_context(cadata=proxy.certificates.pem);conn=HTTPSConnection('127.0.0.1',proxy.server.server_address[1],context=context,timeout=5);auth='Basic '+base64.b64encode(('atlas:'+proxy.token).encode()).decode();conn.set_tunnel('127.0.0.1',tls.server_address[1],headers={'Proxy-Authorization':auth});conn.request('GET','/echo?q=tls');response=conn.getresponse();self.assertEqual(response.status,200);self.assertEqual(response.read(),b'echo tls');conn.close()
            invalid=fetch(Scope({**config,'ca_pem':''}),tlsurl+'/');self.assertEqual(invalid['error'],'TLS validation failed')
        finally:tls.shutdown();tls.server_close()
    def test_schema1_migration_backup_and_interrupted_run_history(self):
        w=self.store.get(self.w['id']);w['web_runs']=[{'id':'previous','state':'running'}];self.store._save(w)
        con=sqlite3.connect(self.store.path);con.execute('PRAGMA user_version=1');con.close();before=self.store.get(self.w['id'])
        reopened=Store(self.store.path);after=reopened.get(self.w['id']);self.assertEqual(after['observations'],before['observations']);self.assertEqual(after['web_runs'][0]['state'],'interrupted')
        backups=list(self.store.path.parent.glob('*before-schema2-*.sqlite3'));self.assertEqual(len(backups),1);con=sqlite3.connect(backups[0]);self.assertEqual(con.execute('PRAGMA user_version').fetchone()[0],1);original=json.loads(con.execute('SELECT body FROM workspaces').fetchone()[0]);con.close();self.assertEqual(original,before)
    def test_redacted_exports_hide_run_target_and_scope(self):
        run=self.tools.start(self.w['id'],'scanner',self.config);self.terminal(run);export=json.dumps(self.store.export(self.w['id']));self.assertNotIn(self.url,export);self.assertEqual(json.loads(export)['web_runs'][0]['plan'],'[withheld]')


if __name__=='__main__':unittest.main()
