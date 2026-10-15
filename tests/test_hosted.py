"""Hosted authentication, terminal ownership/scope, capture and Linux PTY contracts."""
import base64, http.client, json, os, tempfile, threading, time, unittest, uuid
from pathlib import Path
from unittest.mock import patch
from atlas.hosted_auth import HostedAuth, save_password, public_origin
from atlas.host_operations import command, operation, scope_config, terminal_text, plan_digest
from atlas.importers import ImportProblem
from atlas.server import AtlasServer
from atlas.store import Store
from atlas.terminal import Terminals


class FixtureConnection(http.client.HTTPConnection):
    """Deliver the fixture request together, including header-rejected bodies.

    Windows can reset a socket when the server rejects headers before the
    client's separately sent body arrives. Keep the same request/response
    assertions without making this fixture depend on packet scheduling.
    """
    def send(self,data):
        if not hasattr(self,'fixture_bytes'):self.fixture_bytes=[]
        self.fixture_bytes.append(data)
    def flush(self):super().send(b''.join(self.fixture_bytes))


class HostedTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.password='synthetic-hosted-password-42'
        save_password(self.root/'operator-auth.json',self.password)
        self.auth=HostedAuth('https://atlas.example.test',self.root/'operator-auth.json')
        self.store=Store(self.root/'atlas.sqlite3');self.server=AtlasServer(('127.0.0.1',0),self.store,hosted=self.auth)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def request(self,path,data=None,cookie='',nonce='',origin=True,host='atlas.example.test',proto='https'):
        connection=FixtureConnection('127.0.0.1',self.server.server_address[1],timeout=10)
        headers={'Host':host,'X-Forwarded-Proto':proto}
        if data is not None:headers['Content-Type']='application/json'
        if origin:headers['Origin']='https://atlas.example.test'
        if cookie:headers['Cookie']=cookie
        if nonce:headers['X-Atlas-Nonce']=nonce
        connection.request('POST' if data is not None else 'GET',path,json.dumps(data) if data is not None else None,headers)
        connection.flush()
        response=connection.getresponse();body=response.read();code=response.status;head=dict(response.getheaders());connection.close()
        return code,head,json.loads(body) if head.get('Content-Type','').startswith('application/json') else body.decode()
    def login(self):
        code,headers,_=self.request('/api/login',{'password':self.password});self.assertEqual(code,200)
        cookie=headers['Set-Cookie'].split(';')[0]
        code,_,session=self.request('/api/session',cookie=cookie);self.assertEqual(code,200)
        return cookie,session['nonce']
    def test_unauthenticated_hosted_access_and_forwarded_identity(self):
        self.assertEqual(self.request('/api/workspaces')[0],401)
        code,headers,html=self.request('/');self.assertEqual(code,200);self.assertIn('login-password',html);self.assertNotIn('Set-Cookie',headers)
        self.assertEqual(self.request('/api/login',{'password':self.password},host='evil.test')[0],403)
        self.assertEqual(self.request('/api/login',{'password':self.password},proto='http')[0],403)
        self.assertEqual(self.request('/api/login',{'password':self.password},origin=False)[0],403)
    def test_password_nonce_session_isolation_logout_and_cookie_flags(self):
        cookie,nonce=self.login();other,other_nonce=self.login();self.assertNotEqual(cookie,other);self.assertNotEqual(nonce,other_nonce)
        self.assertEqual(self.request('/api/create',{'name':'fixture'},cookie=cookie,nonce=other_nonce)[0],403)
        self.assertEqual(self.request('/api/create',{'name':'fixture'},cookie=cookie,nonce=nonce)[0],200)
        code,headers,_=self.request('/api/logout',{},cookie=cookie,nonce=nonce);self.assertEqual(code,200);self.assertIn('Secure',headers['Set-Cookie']);self.assertIn('HttpOnly',headers['Set-Cookie']);self.assertIn('Max-Age=0',headers['Set-Cookie'])
        self.assertEqual(self.request('/api/workspaces',cookie=cookie)[0],401);self.assertEqual(self.request('/api/workspaces',cookie=other)[0],200)
    def test_wrong_password_limit_and_expired_session(self):
        for _ in range(5):self.assertIsNone(self.auth.login('synthetic-wrong-password'))
        with self.assertRaises(ImportProblem):self.auth.login(self.password)
        self.auth.attempts.clear();token,_=self.auth.login(self.password);self.auth.clock=lambda:time.time()+9*3600
        self.assertIsNone(self.auth.session('atlas_session='+token))
    def test_invalid_public_origin_and_protected_hash(self):
        for url in ('http://atlas.test','https://user:pw@atlas.test','https://atlas.test/path','https://atlas.test/?token=x'):
            with self.assertRaises(ImportProblem):public_origin(url)
        with self.assertRaises(FileExistsError):save_password(self.root/'operator-auth.json',self.password)
        self.assertNotIn(self.password,(self.root/'operator-auth.json').read_text())
    def test_capture_attaches_existing_asset_scrubs_and_exports(self):
        w=self.store.create('Capture fixture','Synthetic');w=self.store.import_file(w['id'],json.dumps({'format':'atlas-evidence/1','entities':[{'key':'host','label':'Fixture','addresses':['192.0.2.1']}],'observations':[]}), 'manual.json','atlas',{})['workspace'];subject=w['entities'][0]['id']
        result=self.store.capture_selection(w['id'],{'subject':subject,'source':'browser-selection','title':'Reviewable evidence','text':'Cookie: synthetic=private-value\n<svg onload=alert(1)> observed'}, {'run_id':'owned-run','url':'https://192.0.2.9/protected','route':{'source':'192.0.2.11'}})
        self.assertEqual(len(result['workspace']['entities']),1);self.assertIn('[redacted]',str(result['workspace']['observations']));self.assertNotIn('private-value',json.dumps(result))
        self.assertNotIn('<svg',json.dumps(self.store.export(w['id'])))
        self.assertNotIn('192.0.2.9',json.dumps(self.store.export(w['id'])));self.assertNotIn('192.0.2.11',json.dumps(self.store.export(w['id'])));self.assertEqual(self.store.export(w['id'])['imports'][-1]['native_context'],'[withheld]')
        with self.assertRaises(ImportProblem):self.store.capture_selection(w['id'],{'subject':'other','source':'browser-selection','title':'x','text':'x'})
    def test_terminal_cross_workspace_and_owner_are_denied(self):
        manager=self.server.terminals;fake=type('Session',(),{'workspace':'a','owner':'first'})();manager.sessions['fixed']=fake
        self.assertIs(manager.get('a','first','fixed'),fake)
        for workspace,owner in [('b','first'),('a','second')]:
            with self.assertRaises(ImportProblem):manager.get(workspace,owner,'fixed')
        manager.sessions.clear()

    def test_large_inventory_reports_omission_instead_of_silent_truncation(self):
        from atlas.vulnerability_match import candidates
        workspace={'observations':[{'id':str(i),'subject':'fixture','kind':'OS fingerprint','status':'inferred','value':{'cpe':['cpe:2.3:o:fixture:system:'+str(i)+':*:*:*:*:*:*:*']}} for i in range(107)]}
        self.assertEqual(len(candidates(workspace)),100)
        with patch.object(self.store,'get',return_value=workspace):result=self.server.vulnerability.status('synthetic')
        self.assertEqual(result['inventory_coverage']['total'],107);self.assertEqual(result['inventory_coverage']['shown'],100);self.assertEqual(result['inventory_coverage']['omitted'],7)


class OperationTests(unittest.TestCase):
    def setUp(self):self.scope=scope_config({'targets':['192.0.2.10'],'profiles':['service-enumeration','http-headers'],'interface':'tun0'})
    def test_fixed_argv_scope_and_no_shell_or_redirects(self):
        plan=operation({'profile':'service-enumeration','target':'192.0.2.10','ports':'80,443,22-23','timeout':30},self.scope)
        argv=command(plan,'result.xml');self.assertIn('-sT',argv);self.assertIn('22,23,80,443',argv);self.assertNotIn('--script',argv)
        plan=operation({'profile':'http-headers','target':'192.0.2.10','url':'https://owned.example.test/login'},self.scope);argv=command(plan,'headers.txt')
        self.assertIn('owned.example.test:443:192.0.2.10',argv);self.assertNotIn('-L',argv);self.assertNotIn('-k',argv);self.assertEqual(argv[1],'--disable')
    def test_malicious_operation_fields_and_unscoped_targets_rejected(self):
        for value in ({'profile':'service-enumeration','target':'192.0.2.11','ports':'22'},{'profile':'service-enumeration','target':'192.0.2.10','ports':'22;id'},{'profile':'service-enumeration','target':'192.0.2.10','ports':'22','command':'id'},{'profile':'http-headers','target':'192.0.2.10','url':'http://user:pw@owned.test/'},{'profile':'http-headers','target':'192.0.2.10','url':'http://192.0.2.11/'}):
            with self.assertRaises(ImportProblem):operation(value,self.scope)
    def test_output_escape_and_sensitive_header_scrubbing(self):
        result=terminal_text('\x1b]52;c;secret\x07Cookie: a=secret\nAuthorization: Bearer secret\nfixture')
        self.assertNotIn('secret',result);self.assertNotIn('\x1b',result);self.assertIn('fixture',result)


@unittest.skipUnless(os.name=='posix' and os.geteuid()!=0 if hasattr(os,'geteuid') else False,'Linux PTY execution requires an unprivileged Linux host')
class LinuxTerminalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.store=Store(Path(self.temp.name)/'atlas.sqlite3');self.workspace=self.store.create('PTY fixture','No target contact')['id'];self.manager=Terminals(self.store)
    def tearDown(self):self.manager.shutdown();self.temp.cleanup()
    def test_real_controlling_terminal_input_output_resize_and_stop(self):
        request=uuid.uuid4().hex;result=self.manager.start(self.workspace,'owner',{'authorized':True,'request_id':request});session=self.manager.get(self.workspace,'owner',result['id'])
        session.input("printf 'ATLAS_PTY_FIXTURE\\n'; tty\n");deadline=time.monotonic()+5;output=b''
        while time.monotonic()<deadline:
            result=session.status();output=base64.b64decode(result['data'])
            if b'ATLAS_PTY_FIXTURE' in output and b'/dev/pts/' in output:break
            time.sleep(.05)
        self.assertIn(b'/dev/pts/',output);self.assertIn(b'ATLAS_PTY_FIXTURE',output);self.assertNotIn(b'no job control',output)
        session.resize(30,120);self.assertEqual(self.manager.start(self.workspace,'owner',{'authorized':True,'request_id':request})['id'],session.id)
        session.stop();self.assertIsNotNone(session.process.poll());self.assertEqual(self.store.web_runs(self.workspace)[0]['state'],'stopped')
    def test_route_mismatch_does_not_start_a_scan(self):
        with patch('atlas.terminal.route_to',side_effect=ImportProblem('VPN route mismatch')):
            with self.assertRaises(ImportProblem):self.manager.preview({'workspace':self.workspace,'interface':'tun0','operation':{'profile':'tcp-discovery','target':'192.0.2.10'}})
        self.assertEqual(self.store.web_runs(self.workspace),[])

    def wait_result(self,session):
        deadline=time.monotonic()+25
        while not session.closed and time.monotonic()<deadline:
            session.status();time.sleep(.05)
        self.assertTrue(session.closed,'Configured operation failed to finish in its bounded fixture window')
        return self.store.web_runs(self.workspace)[0]

    def test_real_scoped_header_operation_auto_intake_no_redirect_and_redaction(self):
        from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
        calls=[]
        class Fixture(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_HEAD(self):
                calls.append(self.path);self.send_response(302);self.send_header('Location','http://127.0.0.1:1/outside');self.send_header('Set-Cookie','session=synthetic-private-value');self.end_headers()
        http=ThreadingHTTPServer(('127.0.0.1',0),Fixture);thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
        try:
            data={'workspace':self.workspace,'interface':'lo','operation':{'profile':'http-headers','target':'127.0.0.1','url':'http://owned.example.test:'+str(http.server_port)+'/fixture','timeout':15}}
            preview=self.manager.preview(data,'owner');data.update(authorized=True,request_id=uuid.uuid4().hex,digest=preview['digest'],context_token=preview['context_token'])
            result=self.manager.start(self.workspace,'owner',data);session=self.manager.get(self.workspace,'owner',result['id']);run=self.wait_result(session)
            self.assertEqual(calls,['/fixture']);self.assertEqual(run['state'],'completed');self.assertEqual(run['requests'],1);self.assertEqual(len(run['import_ids']),1)
            workspace=self.store.get(self.workspace);self.assertNotIn('synthetic-private-value',json.dumps(workspace));self.assertIn('[redacted]',json.dumps(workspace));self.assertEqual(workspace['imports'][0]['intake_mode'],'host live');self.assertIn('retained on the Linux execution host',workspace['imports'][0]['raw_reference']);self.assertEqual(len(workspace['entities']),1)
            self.assertIn('synthetic-private-value',session.artifact.read_text());self.assertEqual(session.artifact.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ImportProblem):self.manager.delete_workspace(self.workspace,'wrong confirmation')
            self.assertTrue(session.artifact.exists());self.manager.delete_workspace(self.workspace,'PTY fixture');self.assertFalse(session.artifact.exists())
        finally:http.shutdown();http.server_close();thread.join()

    def test_real_nmap_loopback_selected_port_import_preserves_tool_version(self):
        import socket
        import shutil
        if not shutil.which('nmap'):self.skipTest('Nmap not installed on this Linux validation host')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        data={'workspace':self.workspace,'interface':'lo','operation':{'profile':'service-enumeration','target':'127.0.0.1','ports':str(port),'timeout':15}}
        preview=self.manager.preview(data,'owner');data.update(authorized=True,request_id=uuid.uuid4().hex,digest=preview['digest'],context_token=preview['context_token'])
        result=self.manager.start(self.workspace,'owner',data);session=self.manager.get(self.workspace,'owner',result['id']);run=self.wait_result(session)
        self.assertEqual(run['state'],'completed');self.assertIsNone(run['requests']);self.assertEqual(len(run['import_ids']),1)
        workspace=self.store.get(self.workspace);self.assertRegex(workspace['imports'][0]['source_version'],r'^7\.');self.assertEqual(workspace['entities'][0]['addresses'],['127.0.0.1'])

    def test_changed_request_id_plan_is_rejected_and_browser_lease_stops_process(self):
        request=uuid.uuid4().hex;result=self.manager.start(self.workspace,'owner',{'authorized':True,'request_id':request});session=self.manager.get(self.workspace,'owner',result['id'])
        plan={'profile':'tcp-discovery','target':'127.0.0.1','timeout':15,'interface':'lo'}
        with self.assertRaises(ImportProblem):self.manager.start(self.workspace,'owner',{'authorized':True,'request_id':request,'interface':'lo','operation':{k:v for k,v in plan.items() if k!='interface'},'digest':plan_digest(plan)})
        session.last_seen=time.monotonic()-36;deadline=time.monotonic()+4
        while not session.closed and time.monotonic()<deadline:time.sleep(.05)
        self.assertTrue(session.closed);self.assertIn('lease expired',session.reason);self.assertIsNotNone(session.process.poll())

    def test_zero_exit_incomplete_nmap_output_is_retained_as_partial(self):
        from atlas.terminal import Terminal
        session=object.__new__(Terminal);session.manager=self.manager;session.workspace=self.workspace;session.plan={'profile':'tcp-discovery','target':'127.0.0.1','interface':'lo'};session.route={'interface':'lo'};session.reason=''
        session.run=self.store.start_web_run(self.workspace,'terminal-operation',{});session.id=session.run['id'];session.artifact=Path(self.temp.name)/'incomplete.xml';session.artifact.write_text('<nmaprun version="7.95"><runstats><finished exit="success"/></runstats></nmaprun>');session.process=type('Ended',(),{'returncode':0})()
        session.intake();self.assertIn('Partial Nmap',session.reason);self.assertEqual(self.store.web_runs(self.workspace)[0]['import_ids'],[])

if __name__=='__main__':unittest.main()
