"""Owned synthetic authentication/audit corpus; no external targets or real secrets."""
import html
import json
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
import base64
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import parse_qs,urlsplit,urlencode
from unittest.mock import patch

from atlas.importers import ImportProblem
from atlas.importers import parse
from atlas.store import Store
from atlas.web_tools import WebTools
from atlas.web_auth import AuthSession
from atlas.web_transport import Scope,fetch
from atlas.web_advanced import transform,token_measurements,payload_plan,api_inventory
from atlas.web_proxy import Proxy

TEMP=Path(__file__).resolve().parent.parent/'work/test-temp';TEMP.mkdir(parents=True,exist_ok=True)
PASSWORD='fixture-password-ONLY';COOKIE='fixture-cookie-ONLY';CSRF='fixture-csrf-ONLY';MARKER='SIGNED_IN_FIXTURE';PROTECTED='PRIVATE_RECORD_FIXTURE'


class AuthFixture(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def reply(self,status,body,headers=None):
        raw=body.encode();self.send_response(status);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(raw)))
        for key,value in (headers or []):self.send_header(key,value)
        self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        parts=urlsplit(self.path);path=parts.path;query=parse_qs(parts.query);self.server.seen.append({'path':self.path,'cookie':self.headers.get('Cookie',''),'auth':self.headers.get('Authorization','')})
        signed=COOKIE in self.headers.get('Cookie','') or self.headers.get('Authorization')=='Bearer '+COOKIE
        if self.server.expired:signed=False
        if path=='/login':return self.reply(200,'<input type="hidden" name="csrf" value="'+CSRF+'">',[('X-Login-Token',CSRF)])
        if path=='/guard':return self.reply(200 if signed else 401,MARKER if signed else 'Login required')
        if path=='/private/path-guard':return self.reply(200 if signed else 401,MARKER if signed else 'Login required')
        if path=='/public-guard':return self.reply(200,MARKER)
        if path=='/auto-login':return self.reply(200,'<script>fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:"synthetic",password:"'+PASSWORD+'",csrf:"'+CSRF+'"})}).then(()=>fetch("/guard")).then(r=>r.text()).then(t=>document.body.dataset.loaded=t)</script>')
        if path=='/auto-path-login':return self.reply(200,'<script>fetch("/path-login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:"synthetic",password:"'+PASSWORD+'",csrf:"'+CSRF+'"})}).then(()=>fetch("/private/path-guard")).then(r=>r.text()).then(t=>document.body.dataset.loaded=t)</script>')
        if path.startswith('/private') and not signed:return self.reply(401,'Login required')
        if path=='/private':return self.reply(200,'<a href="'+self.server.leak_origin+'/echo">Auxiliary</a>' if self.server.leak_origin else '<a href="/private/sql?q=base">SQL</a><a href="/private/template?q=base">Template</a><a href="/private/html?q=base">HTML</a><a href="/private/fixed?q=base">Fixed</a>')
        if path=='/private/expire':self.server.expired=True;return self.reply(200,'Expired after this request')
        q=query.get('q',['base'])[0]
        if path.endswith('/sql'):
            body="sqlite3.OperationalError: synthetic SQL syntax" if "'" in q else 'baseline'
        elif path.endswith('/template'):
            body=re.sub(r'\{\{(\d+)\*(\d+)\}\}',lambda m:str(int(m[1])*int(m[2])),q)
        elif path.endswith('/html'):body=q
        elif path.endswith('/fixed'):body=html.escape(q)
        elif path=='/open':body=PROTECTED
        elif path=='/private/record':body=PROTECTED
        elif path=='/echo':body=self.headers.get('Cookie','')+' '+self.headers.get('Authorization','')
        elif path=='/redirect':return self.reply(302,'',[('Location',self.server.outside)])
        else:body='ordinary fixture content'
        headers=[]
        if path=='/cors':headers=[('Access-Control-Allow-Origin',self.headers.get('Origin','https://owned.example')),('Access-Control-Allow-Credentials','true')]
        if self.server.leak_origin and path=='/private':body='<a href="'+self.server.leak_origin+'/echo">Auxiliary</a>'
        return self.reply(200,body,headers)
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0'))).decode();self.server.posts.append(body)
        if self.path in ('/login','/path-login'):
            try:obj={k:v[0] for k,v in parse_qs(body).items()} if 'application/x-www-form-urlencoded' in self.headers.get('Content-Type','') else json.loads(body)
            except ValueError:return self.reply(400,'invalid JSON')
            if obj!={'username':'synthetic','password':PASSWORD,'csrf':CSRF}:return self.reply(401,'Invalid credentials')
            self.server.expired=False;self.server.logins+=1
            return self.reply(200,json.dumps({'access_token':COOKIE,'echo_password':PASSWORD}),[('Set-Cookie','session='+COOKIE+'; HttpOnly; Path='+('/private' if self.path=='/path-login' else '/'))])
        if self.path=='/private/json':
            if COOKIE not in self.headers.get('Cookie',''):return self.reply(401,'Login required')
            return self.reply(200,str(json.loads(body).get('q','')))
        return self.reply(200,body)


def auth_fixture(port=0,tls=None):
    server=ThreadingHTTPServer(('127.0.0.1',port),AuthFixture);server.seen=[];server.posts=[];server.expired=False;server.logins=0;server.leak_origin='';server.outside='http://127.0.0.1:1/outside'
    if tls:server.socket=tls.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start();return server


class AdvancedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEMP);self.store=Store(Path(self.temp.name)/'atlas.sqlite3');self.workspace=self.store.create('Advanced synthetic','Owned loopback fixtures');self.tools=WebTools(self.store,8765);self.target=auth_fixture();self.url=f'http://127.0.0.1:{self.target.server_address[1]}'
        self.config={'url':self.url+'/private','authorized':True,'max_requests':80,'max_seconds':60,'delay_ms':250,'max_depth':2,'path_prefix':'/','retain_body':True}
        self.auth={'check_url':self.url+'/guard','success_text':MARKER,'steps':[{'url':self.url+'/login','extract':{'csrf':{'from':'hidden','name':'csrf'}}},{'url':self.url+'/login','method':'POST','headers':[{'name':'Content-Type','value':'application/json'}],'body':json.dumps({'username':'synthetic','password':PASSWORD,'csrf':'{{csrf}}'}),'extract':{'bearer':{'from':'json','name':'access_token'}}}]}
    def tearDown(self):self.tools.shutdown();self.target.shutdown();self.target.server_close();self.temp.cleanup()
    def terminal(self,run):
        for _ in range(1300):
            row=next(r for r in self.store.web_runs(self.workspace['id']) if r['id']==run['id'])
            if row['state'] not in ('queued','running'):return row
            time.sleep(.05)
        self.fail('Run did not finish')
    def scan(self,**changes):return self.terminal(self.tools.start(self.workspace['id'],'scanner',{**self.config,'auth':self.auth,**changes}))
    def test_authenticated_crawl_audit_controls_and_direct_assessment_findings(self):
        result=self.scan(audit_crawl=True,checks=['sql-error','template-expression','html-reflection'],active_audit=True)
        self.assertEqual(result['state'],'completed',result);self.assertEqual(result['audited_endpoints'],5)
        workspace=self.store.get(self.workspace['id']);types={f['external_id'] for f in workspace['findings']};self.assertEqual(types,{'atlas-sql-error-differential','atlas-template-expression','atlas-html-reflection'})
        fixed_ids={e['id'] for e in workspace['entities'] if e['label'].endswith('/fixed')};self.assertFalse(any(f['subject'] in fixed_ids for f in workspace['findings']))
        self.assertTrue(all(f['validation']=='scanner-reported' for f in workspace['findings']));self.assertTrue(all(f['import_id'] for f in workspace['findings']))
        controls=[o['value'] for o in workspace['observations'] if o['kind']=='selected parameter test'];self.assertTrue(any(len(o['control_event_ids'])==2 for o in controls))
        stored=json.dumps(workspace);export=json.dumps(self.store.export(self.workspace['id'],True));raw=Path(self.store.path).read_bytes()
        for secret in (PASSWORD,COOKIE,CSRF):self.assertFalse(secret in stored,'Session secret persisted');self.assertFalse(secret in export,'Session secret exported');self.assertFalse(secret.encode() in raw,'Session secret remained in database')
        self.assertGreater(result['requests'],result['audited_endpoints']);self.assertTrue(any(o['kind']=='web authentication context' and o['value']['session_verified'] for o in workspace['observations']))
    def test_wrong_credentials_no_audit_and_public_guard_rejected(self):
        self.auth['steps'][1]['body']=self.auth['steps'][1]['body'].replace(PASSWORD,'wrong-password')
        result=self.scan();self.assertEqual(result['state'],'failed');self.assertEqual(result['audited_endpoints'],0);self.assertEqual(self.store.get(self.workspace['id'])['findings'],[])
        result=self.scan(auth={**self.auth,'check_url':self.url+'/public-guard'});self.assertEqual(result['state'],'failed');self.assertIn('anonymously',result['reason'])
    def test_session_loss_stops_without_falling_back_to_anonymous(self):
        session={'check_url':self.url+'/guard','success_text':MARKER,'headers':'Cookie: session='+COOKIE}
        result=self.scan(auth=session,url=self.url+'/private/expire',paths=['/private/sql?q=base'],checks=['sql-error'],active_audit=True)
        self.assertEqual(result['state'],'partial');self.assertIn('Authentication was lost',result['reason']);self.assertFalse(any("ATLAS" in row['path'] for row in self.target.seen));self.assertEqual(result['findings'],0)
    def test_login_refreshes_are_bounded_and_counted(self):
        result=self.scan(url=self.url+'/private/expire',paths=['/private/record']);self.assertEqual(result['state'],'completed');self.assertEqual(result['session_refreshes'],1);self.assertEqual(self.target.logins,2)
    def test_credentials_cannot_leak_to_auxiliary_origin_or_redirect(self):
        outside=auth_fixture();other=f'http://127.0.0.1:{outside.server_address[1]}';self.target.leak_origin=other
        try:
            result=self.scan(extra_origins=[other+'/'],audit_crawl=True);self.assertEqual(result['state'],'completed');self.assertTrue(outside.seen);self.assertTrue(all(not e['cookie'] and not e['auth'] for e in outside.seen))
            session=AuthSession(Scope({**self.config,'extra_origins':[other+'/']}),{**self.auth,'headers':'Authorization: Bearer '+COOKIE})
            headers=session.headers(other+'/echo',[{'name':'X-Api-Key','value':'fixture-secret'}]);self.assertFalse(any(h['name'].lower() in ('authorization','cookie','x-api-key') for h in headers));session.clear()
        finally:outside.shutdown();outside.server_close()
    def test_cookie_path_secure_expiry_and_origin_boundaries(self):
        session=AuthSession(Scope(self.config),{'check_url':self.url+'/guard','success_text':MARKER,'cookies':[{'origin':self.url,'name':'session','value':COOKIE,'path':'/private','secure':False,'expires':time.time()+60}]})
        self.assertTrue(any(h['name']=='Cookie' for h in session.headers(self.url+'/private/record')));self.assertFalse(any(h['name']=='Cookie' for h in session.headers(self.url+'/guard')))
        session.clear()
        for secure,expires in ((True,-1),(False,time.time()-10)):
            session=AuthSession(Scope(self.config),{'check_url':self.url+'/guard','success_text':MARKER,'cookies':[{'origin':self.url,'name':'session','value':COOKIE,'path':'/','secure':secure,'expires':expires}]});self.assertFalse(any(h['name']=='Cookie' for h in session.headers(self.url+'/guard')));session.clear()
    def test_extracted_bearer_and_reflected_short_header_secret_are_withheld(self):
        self.auth['headers']='Authorization: Bearer {{bearer}}'
        result=self.scan(url=self.url+'/echo');self.assertEqual(result['state'],'completed');self.assertFalse(COOKIE in json.dumps(self.store.get(self.workspace['id'])))
        session=AuthSession(Scope(self.config),{'check_url':self.url+'/guard','success_text':MARKER,'headers':'Authorization: Bearer ab'})
        event={'id':'abc123','url':self.url+'/echo','response':{'body':'ab ab','body_sha256':'abcd'}};scrubbed=session.scrub(event);self.assertEqual(scrubbed['id'],'abc123');self.assertEqual(scrubbed['response']['body_sha256'],'abcd');self.assertNotIn('ab',scrubbed['response']['body']);session.clear()
    def test_response_header_extraction_and_form_login_substitution(self):
        self.auth['steps'][0]['extract']={'csrf':{'from':'header','name':'X-Login-Token'}};self.auth['steps'][1]['headers']=[{'name':'Content-Type','value':'application/x-www-form-urlencoded'}];self.auth['steps'][1]['body']=urlencode({'username':'synthetic','password':PASSWORD,'csrf':'{{csrf}}'})
        result=self.scan();self.assertEqual(result['state'],'completed');self.assertEqual(self.target.logins,1);self.assertFalse(CSRF in json.dumps(self.store.get(self.workspace['id'])))
    def test_response_interception_saves_upstream_and_labels_downstream_edits(self):
        import socket
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        proxy=Proxy(self.tools,self.workspace['id'],{**self.config,'url':self.url+'/open','proxy_port':port,'intercept_response':True});self.tools.proxies[proxy.run['id']]=proxy;received={}
        with self.assertRaises(ImportProblem):self.tools.start(self.workspace['id'],'scanner',{**self.config,'url':f'http://127.0.0.1:{port}/'})
        def client():
            conn=HTTPConnection('127.0.0.1',port,timeout=5);conn.request('GET',self.url+'/open',headers={'Proxy-Authorization':'Basic '+base64.b64encode(('atlas:'+proxy.token).encode()).decode()});response=conn.getresponse();received.update(status=response.status,body=response.read().decode());conn.close()
        worker=threading.Thread(target=client);worker.start()
        for _ in range(100):
            pending=proxy.status()['pending']
            if pending:break
            time.sleep(.02)
        self.assertEqual(pending[0]['phase'],'response');self.assertTrue(self.store.get(self.workspace['id'])['imports'])
        with self.assertRaises(ImportProblem):proxy.decide(pending[0]['id'],'forward',{'status':204,'body':'invalid'})
        proxy.decide(pending[0]['id'],'forward',{'status':201,'headers':'Content-Type: text/plain','body':'operator edited'});worker.join(5);self.assertEqual(received,{'status':201,'body':'operator edited'})
        workspace=self.store.get(self.workspace['id']);responses=[o['value'] for o in workspace['observations'] if o['kind']=='HTTP response'];self.assertEqual([r['status'] for r in responses],[200,201]);edited=next(o['value'] for o in workspace['observations'] if o['kind']=='live request interception' and o['value'].get('response_intercepted'));self.assertTrue(edited['upstream_response_event_id']);self.assertEqual(proxy.count,1);proxy.close()
    def test_transient_sessions_tenant_expiry_and_discard(self):
        session=self.tools.save_session(self.workspace['id'],{**self.config,'auth':self.auth,'session_label':'Fixture session'});key=session['id'];self.assertEqual(self.tools.session_list(self.workspace['id'])[0]['id'],key)
        other=self.store.create('Other','fixture')
        with self.assertRaises(ImportProblem):self.tools.start(other['id'],'scanner',{**self.config,'session_id':key})
        self.tools.sessions[key]['expires']=0
        with self.assertRaises(ImportProblem):self.tools.start(self.workspace['id'],'scanner',{**self.config,'session_id':key})
        self.assertNotIn(PASSWORD,json.dumps(self.store.get(self.workspace['id'])))
    def test_anonymous_authorization_control_distinguishes_protected_and_open(self):
        result=self.scan(url=self.url+'/private/record',paths=['/open'],checks=['authorization'],protected_marker=PROTECTED,active_audit=True);self.assertEqual(result['state'],'completed');self.assertEqual(result['findings'],1)
        finding=self.store.get(self.workspace['id'])['findings'][0];self.assertEqual(finding['external_id'],'atlas-authorization-comparison')
    def test_cors_and_custom_declarative_rule_controls(self):
        rule={'id':'literal','name':'Fixture literal','match':{'status':200,'body_contains':'ordinary fixture content'}}
        result=self.scan(url=self.url+'/cors',checks=['cors-origin'],active_audit=True,custom_checks=[rule]);self.assertEqual(result['findings'],2)
        with self.assertRaises(ImportProblem):self.tools.start(self.workspace['id'],'scanner',{**self.config,'custom_checks':[{'id':'code','name':'No','match':{'regex':'.*'}}]})
        with self.assertRaises(ImportProblem):self.tools.start(self.workspace['id'],'scanner',{**self.config,'custom_checks':[rule,rule]})
    def test_json_insertion_and_multi_position_request_modes(self):
        result=self.scan(url=self.url+'/private/json',audit_requests=[{'url':self.url+'/private/json','method':'POST','headers':[{'name':'Content-Type','value':'application/json'}],'body':'{"q":"base"}'}],checks=['html-reflection'],active_audit=True)
        self.assertEqual(result['state'],'completed');self.assertEqual(result['findings'],1)
        result=self.terminal(self.tools.start(self.workspace['id'],'matrix',{**self.config,'url':self.url+'/private/html?q=base&a=old','auth':self.auth,'active_audit':True,'attack_mode':'cluster','positions':[{'location':'query','name':'q','payloads':['ONE','TWO']},{'location':'query','name':'a','payloads':['A','B']}]}));self.assertEqual(result['state'],'completed');self.assertEqual(result['requests'],10)
    def test_limits_and_cancel_keep_auth_evidence(self):
        result=self.scan(max_requests=2);self.assertEqual(result['state'],'partial');self.assertEqual(result['requests'],2);self.assertEqual(result['audited_endpoints'],0)
        run=self.tools.start(self.workspace['id'],'scanner',{**self.config,'auth':self.auth,'delay_ms':1000});time.sleep(.1);self.tools.stop(self.workspace['id'],run['id']);result=self.terminal(run);self.assertEqual(result['state'],'cancelled');self.assertGreaterEqual(len(result['import_ids']),1)
    def test_codecs_measurements_and_inert_openapi(self):
        value='Hello <é> & "fixture"'
        for codec in ('base64','url','html','hex','json'):self.assertEqual(transform(transform(value,codec+'-encode'),codec+'-decode'),value)
        for codec,value in (('base64-decode','!'),('hex-decode','zz'),('url-decode','%QX'),('json-decode','{}')):
            with self.assertRaises(ImportProblem):transform(value,codec)
        metrics=token_measurements(['AAAA','AAAB','AAAA']);self.assertEqual(metrics['duplicate_samples'],1);self.assertEqual(metrics['positions'][0]['empirical_entropy_bits'],0);self.assertNotIn('AAAA',json.dumps(metrics))
        schema={'openapi':'3.1.0','servers':[{'url':'https://outside.example/'}],'paths':{'/guard':{'get':{}},'/item/{id}':{'get':{}},'/login':{'post':{}}}}
        with patch('socket.create_connection',side_effect=AssertionError('Inert schema fetched target')):inventory=api_inventory(schema,Scope(self.config,resolve=False))
        self.assertEqual(inventory['audit_requests'],[{'url':self.url+'/guard','method':'GET'}]);self.assertEqual(len(inventory['unsupported']),2)
        with self.assertRaises(ImportProblem):api_inventory({'openapi':'3.1.0','paths':{'/guard':{'get':{'parameters':{}}}}},Scope(self.config,resolve=False))
        row={'url':self.url+'/echo?q=x&a=y'};positions=[{'location':'query','name':'q','payloads':['ONE','TWO']},{'location':'query','name':'a','payloads':['A','B']}]
        for mode,count in (('sniper',4),('battering',2),('pitchfork',2),('cluster',4)):self.assertEqual(len(payload_plan(row,{'positions':positions,'attack_mode':mode})),count)
        with self.assertRaises(ImportProblem):payload_plan(row,{'positions':[dict(p,payloads=list(map(str,range(20)))) for p in positions],'attack_mode':'cluster'})
    def test_web_adapter_revision_appends_new_auth_derivation_without_overwrite(self):
        content=json.dumps({'format':'atlas-web/1','source':'web-proxy','events':[{'id':'revision-fixture','url':self.url+'/guard','response':{'status':200,'headers':[],'body':'ordinary'},'authentication':{'mode':'source-asserted session','session_verified':True}}]})
        legacy=parse(content,'web-proxy');legacy.adapter_version='2';legacy.observations=[o for o in legacy.observations if o['kind']!='web authentication context']
        with patch('atlas.store.parse',return_value=legacy):old=self.store.import_file(self.workspace['id'],content,'fixture.json','web-proxy',{})
        historical=old['workspace']['observations'];new=self.store.import_file(self.workspace['id'],content,'fixture.json','web-proxy',{});self.assertFalse(new['duplicate']);self.assertEqual([i['adapter_version'] for i in new['workspace']['imports']],['2','3']);self.assertTrue(all(o in new['workspace']['observations'] for o in historical));self.assertTrue(any(o['kind']=='web authentication context' for o in new['workspace']['observations']))
    def test_ipv4_mapped_control_and_metadata_targets_are_excluded(self):
        for address,port in (('::ffff:169.254.169.254',80),('::ffff:127.0.0.1',8765)):
            with patch('socket.getaddrinfo',return_value=[(10,1,6,'',(address,port,0,0))]),self.assertRaises(ImportProblem):Scope({**self.config,'url':f'http://[{address}]:{port}/'},8765)


if __name__=='__main__':unittest.main()
