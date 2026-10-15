import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
from http.client import HTTPConnection

from atlas.importers import ImportProblem
from atlas.store import Store
from atlas.web_tools import WebTools
from atlas.web_transport import Scope,fetch
from atlas.web_protocols import available
from atlas.web_socket import WebSocketSession,SocketClient
from atlas.web_oob import OOBReceiver
from atlas.web_proxy import Proxy
from protocol_fixtures import ProtocolFixtures,WebSocketFixture

TEMP=Path(__file__).resolve().parent.parent/'work/test-temp';TEMP.mkdir(parents=True,exist_ok=True)
def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


@unittest.skipUnless(all(available().values()),'Install requirements-protocols.txt for real protocol fixtures')
class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEMP);self.store=Store(Path(self.temp.name)/'atlas.sqlite3');self.workspace=self.store.create('Protocol synthetic','Owned loopback only');self.tools=WebTools(self.store,8765);self.fixture=ProtocolFixtures(self.temp.name);self.config={'url':f'https://127.0.0.1:{self.fixture.h2_port}/','authorized':True,'ca_pem':self.fixture.ca.pem,'max_requests':20,'max_seconds':20,'delay_ms':250}
    def tearDown(self):self.tools.shutdown();self.fixture.close();self.temp.cleanup()
    def test_real_h2_and_h3_tls_methods_headers_and_evidence(self):
        for protocol,target in [('http2',self.fixture.h2_port),('http3',self.fixture.h3_port)]:
            result=self.tools.send(self.workspace['id'],{**self.config,'http_version':protocol,'url':f'https://127.0.0.1:{target}/query?q=secret','method':'POST','body':'protocol body','headers':'Content-Type: text/plain\nAuthorization: Bearer fixture-secret'})
            event=result['event'];self.assertNotIn('error',event,event.get('error'));self.assertEqual(event['response']['status'],200);self.assertEqual(event['response']['body'],'protocol body');self.assertEqual(event['http_version'],'HTTP/2' if protocol=='http2' else 'HTTP/3')
        saved=json.dumps(self.store.get(self.workspace['id']));self.assertNotIn('fixture-secret',saved);self.assertTrue(any(o['kind']=='HTTP transport observation' and o['value']['http_version']=='HTTP/3' for o in self.store.get(self.workspace['id'])['observations']))
    def test_h2_h3_bad_ca_refuse_and_no_second_dns_resolution(self):
        for protocol,target in [('http2',self.fixture.h2_port),('http3',self.fixture.h3_port)]:
            event=fetch(Scope({**self.config,'http_version':protocol,'url':f'https://127.0.0.1:{target}/','ca_pem':''}),f'https://127.0.0.1:{target}/',timeout=2);self.assertIn('error',event)
        scope=Scope(self.config)
        with patch('socket.create_connection',side_effect=OSError('fixture stop')) as connect:fetch(scope,self.config['url'])
        self.assertEqual(connect.call_args.args[0][0],'127.0.0.1')
    def test_websocket_text_binary_replay_scoped_and_metadata(self):
        fixture=WebSocketFixture()
        try:
            url=f'http://127.0.0.1:{fixture.port}/';config={**self.config,'url':url,'ws_url':url.replace('http:','ws:')};session=WebSocketSession(self.tools,self.workspace['id'],config);self.tools.sockets[session.run['id']]=session;session.send('hello');session.send(base64.b64encode(b'\x00binary').decode(),True)
            for _ in range(100):
                if session.message_count>=4:break
                time.sleep(.02)
            self.assertEqual(session.message_count,4);self.assertTrue(any(r['body']=='echo:hello' for r in session.messages));saved=json.dumps(self.store.get(self.workspace['id']));self.assertNotIn('echo:hello',saved);self.assertIn('WebSocket message',saved);self.assertNotIn(base64.b64encode(b'\x00binary').decode(),saved)
            with self.assertRaises(ImportProblem):WebSocketSession(self.tools,self.workspace['id'],{**config,'ws_url':'ws://127.0.0.1:1/outside'})
            session.close()
        finally:fixture.close()
    def test_real_wss_upstream_ca_verification(self):
        fixture=WebSocketFixture(self.fixture.ca.context('127.0.0.1',Path(self.temp.name)))
        try:
            url=f'https://127.0.0.1:{fixture.port}/';client=SocketClient(Scope({**self.config,'url':url}),url.replace('https:','wss:'));client.send('TLS');self.assertEqual(client.receive()['data'],'echo:TLS');client.close()
            with self.assertRaises(Exception):SocketClient(Scope({**self.config,'url':url,'ca_pem':''}),url.replace('https:','wss:'))
        finally:fixture.close()
    def test_authenticated_websocket_budget_scrubbing_and_close_discard(self):
        fixture=WebSocketFixture(required_token='text')
        try:
            origin=f'http://127.0.0.1:{fixture.port}';config={**self.config,'url':origin+'/','ws_url':origin.replace('http:','ws:')+'/socket','retain_body':True,'auth':{'check_url':origin+'/guard','success_text':'WS_SIGNED_IN_FIXTURE','headers':'Authorization: Bearer text'}}
            session=WebSocketSession(self.tools,self.workspace['id'],config);self.tools.sockets[session.run['id']]=session;session.send('text payload')
            for _ in range(100):
                if session.message_count==2:break
                time.sleep(.02)
            self.assertEqual(session.http_requests,3);self.assertEqual(session.message_count,2)
            with self.assertRaises(ImportProblem):session.send('not Base64!',True)
            with self.assertRaises(ImportProblem):session.send('X'*65537)
            session.finding(session.messages[-1]['id'],'Synthetic authenticated WS','info','Owned message response; authorization requires independent review.')
            w=self.store.get(self.workspace['id']);messages=[o['value'] for o in w['observations'] if o['kind']=='WebSocket message'];self.assertTrue(messages);self.assertTrue(all(m['opcode']=='text' for m in messages));self.assertTrue(all('text payload' not in m['body'] for m in messages));self.assertTrue(any(o['kind']=='web authentication context' and o['value']['session_verified'] for o in w['observations']));self.assertEqual(w['findings'][-1]['validation'],'scanner-reported')
            session.close();self.assertEqual(session.messages,[]);self.assertEqual(session.saved_messages,{});self.assertNotIn('auth',session.config)
            before=len([r for r in fixture.seen if not isinstance(r,dict)])
            with self.assertRaises(ImportProblem):WebSocketSession(self.tools,self.workspace['id'],{**config,'max_requests':2})
            self.assertEqual(len([r for r in fixture.seen if not isinstance(r,dict)]),before);run=self.store.web_runs(self.workspace['id'])[-1];self.assertEqual(run['state'],'failed');self.assertEqual(run['requests'],2);self.assertTrue(run['import_ids'])
        finally:fixture.close()
    def test_failed_websocket_handshake_retains_failure_evidence(self):
        fixture=WebSocketFixture(self.fixture.ca.context('127.0.0.1',Path(self.temp.name)))
        try:
            origin=f'https://127.0.0.1:{fixture.port}'
            with self.assertRaises(ImportProblem):WebSocketSession(self.tools,self.workspace['id'],{**self.config,'url':origin+'/','ws_url':origin.replace('https:','wss:')+'/socket','ca_pem':''})
            run=self.store.web_runs(self.workspace['id'])[-1];self.assertEqual(run['state'],'failed');self.assertEqual(run['requests'],1);self.assertTrue(any(o['kind']=='web request failure' for o in self.store.get(self.workspace['id'])['observations']))
        finally:fixture.close()
    def test_http_dns_oob_tokens_direct_findings_expiry_and_unknown_token(self):
        receiver=OOBReceiver(self.tools,self.workspace['id'],{**self.config,'oob_port':port(),'dns_port':port()});self.tools.receivers[receiver.run['id']]=receiver;issued=receiver.allocate(self.config['url'],'q');parts=__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(issued['callback_url']);conn=HTTPConnection(parts.hostname,parts.port);conn.request('POST',parts.path,b'callback secret');response=conn.getresponse();self.assertEqual(response.status,204);response.read();conn.close()
        name=issued['dns_name'];question=b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\x00'+struct.pack('!HH',1,1);packet=b'\x12\x34'+struct.pack('!HHHHH',0x0100,1,0,0,0)+question
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:sock.settimeout(2);sock.sendto(packet,('127.0.0.1',receiver.dns.server_address[1]));answer=sock.recv(512);self.assertEqual(answer[:2],b'\x12\x34')
        self.assertEqual(receiver.count,2);workspace=self.store.get(self.workspace['id']);self.assertEqual(len(workspace['findings']),2);self.assertTrue(all(f['validation']=='scanner-reported' for f in workspace['findings']));self.assertNotIn('callback secret',json.dumps(workspace));self.assertNotIn(parts.path,json.dumps(workspace));self.assertFalse(receiver.observe('0'*48,'HTTP','127.0.0.1','GET',0,hashlib.sha256(b'').hexdigest()))
        receiver.bind_capture(issued['id'],{'id':'probe-fixture'});self.assertTrue(any(o['value'].get('probe_capture_id')=='probe-fixture' for o in self.store.get(self.workspace['id'])['observations'] if o['kind']=='out-of-band interaction'));receiver.close();self.assertFalse(receiver.observe(parts.path.rsplit('/',1)[-1],'HTTP','127.0.0.1','GET',0,''))
        delayed={'id':'delayed-probe-after-receiver-close','url':self.config['url'],'captured_at':__import__('atlas.store',fromlist=['now']).now(),'request':{'method':'POST','headers':[{'name':'X-Probe','value':issued['dns_name']}],'body':'<!DOCTYPE atlas [<!ENTITY probe SYSTEM "'+issued['callback_url']+'">]><atlas>&probe;</atlas>'},'parameters':[],'links':[]}
        self.tools.capture(self.workspace['id'],delayed,'web-workbench',{**self.config,'retain_body':True});saved=json.dumps(self.store.get(self.workspace['id']));token=parts.path.rsplit('/',1)[-1];self.assertNotIn(token,saved);self.assertNotIn(token.encode(),Path(self.store.path).read_bytes());self.assertEqual(receiver.tokens,{})
    def test_real_proxy_websocket_intercept_edit_both_directions(self):
        import wsproto
        from wsproto import events
        import threading
        fixture=WebSocketFixture();url=f'http://127.0.0.1:{fixture.port}/socket';proxy=Proxy(self.tools,self.workspace['id'],{**self.config,'url':url,'proxy_port':port()});self.tools.proxies[proxy.run['id']]=proxy;proxy.ws_intercept=True;result={}
        def browser():
            try:
                with socket.create_connection(('127.0.0.1',proxy.server.server_address[1]),5) as sock:
                    sock.settimeout(5);ws=wsproto.WSConnection(wsproto.ConnectionType.CLIENT);auth=b'Basic '+base64.b64encode(('atlas:'+proxy.token).encode());sock.sendall(ws.send(events.Request(host=__import__('urllib.parse',fromlist=['urlsplit']).urlsplit(url).netloc,target=url,extra_headers=[(b'proxy-authorization',auth)])))
                    accepted=False
                    while not accepted:
                        data=sock.recv(65536)
                        if not data:raise RuntimeError('Proxy handshake closed')
                        ws.receive_data(data)
                        for event in ws.events():
                            if isinstance(event,events.AcceptConnection):accepted=True
                    sock.sendall(ws.send(events.TextMessage(data='original')))
                    while True:
                        ws.receive_data(sock.recv(65536))
                        for event in ws.events():
                            if isinstance(event,events.TextMessage):result['body']=event.data;return
            except Exception as exc:result['error']=str(exc)
        worker=threading.Thread(target=browser);worker.start()
        try:
            for expected,replacement in [('to server','edited'),('from server','downstream')]:
                pending=[]
                for _ in range(200):
                    pending=[p for p in proxy.status()['pending'] if p.get('direction')==expected]
                    if pending:break
                    time.sleep(.01)
                self.assertTrue(pending,result);proxy.decide(pending[0]['id'],'forward',{'body':replacement,'binary':False})
            worker.join(5);self.assertEqual(result,{'body':'downstream'});self.assertIn('edited',fixture.seen)
            workspace=self.store.get(self.workspace['id']);messages=[o for o in workspace['observations'] if o['kind']=='WebSocket message'];self.assertEqual(len(messages),4);self.assertTrue(any(o['value'].get('original_message_sha256') for o in messages));self.assertEqual(proxy.count,1)
        finally:proxy.close();fixture.close();worker.join(2)


if __name__=='__main__':unittest.main()
