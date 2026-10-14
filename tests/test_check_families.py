"""Owned vulnerable/fixed canary endpoints; no production scans or private data."""
import hashlib
import html
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs,urlsplit
import urllib.request
import xml.etree.ElementTree as ET

from atlas.store import Store
from atlas.web_tools import WebTools
from atlas.web_oob import OOBReceiver
from test_protocols import port

TEMP=Path(__file__).resolve().parent.parent/'work/test-temp';TEMP.mkdir(parents=True,exist_ok=True)
MARKER='ATLAS_CONTROLLED_CANARY'


class BroadFixture(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def reply(self,status,text,headers=None):
        raw=text.encode();self.send_response(status);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(raw)))
        for name,value in headers or []:self.send_header(name,value)
        self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        p=urlsplit(self.path);fixed=p.path.startswith('/fixed/');kind=p.path.rsplit('/',1)[-1];q=parse_qs(p.query).get('q',['base'])[0]
        if p.path=='/ws-page':
            document='<html><script>const channel=new WebSocket('+json.dumps(self.server.ws_url)+');channel.onopen=()=>{channel.send("NATIVE_BROWSER_WS");channel.send(new Uint8Array([1,2,3]));};channel.onmessage=event=>document.body.dataset.reply=typeof event.data==="string"?event.data:"binary";new WebSocket("ws://127.0.0.1:1/outside");</script><body>Owned JavaScript WebSocket fixture</body></html>'
            raw=document.encode();self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
        if kind=='boolean':return self.reply(200,'baseline true' if fixed or q=='base' or '1=1' in q or '2=2' in q else 'false branch')
        if kind in ('nosql','ldap','xpath'):
            trigger={'nosql':'$atlas_invalid','ldap':'*)','xpath':"'[]"}[kind];error={'nosql':'MongoServerError: unknown operator $atlas_invalid','ldap':'LDAP invalid filter error','xpath':'XPathSyntaxError: invalid expression'}[kind]
            return self.reply(200,error if trigger in q and not fixed else 'ordinary fixed response')
        if kind=='command':
            match=re.fullmatch(r";printf '(ATLAS_CMD_[0-9a-f]{10})%s' \$\(\((\d+)\*(\d+)\)\);",q)
            if match and not fixed:
                # Execute only this verified fixture arithmetic, never arbitrary supplied code.
                code='import sys;sys.stdout.write('+repr(match[1])+"+str("+match[2]+'*'+match[3]+'))';text=subprocess.run([__import__('sys').executable,'-c',code],check=True,capture_output=True,text=True,timeout=2).stdout;return self.reply(200,text)
            return self.reply(200,'ordinary fixed response')
        if kind=='file':
            target=(self.server.root/'webroot'/q).resolve();allowed=self.server.root/'webroot' if fixed else self.server.root
            if target.is_relative_to(allowed.resolve()) and target.is_file():return self.reply(200,target.read_text(encoding='utf-8'))
            return self.reply(404,'canary unavailable')
        if kind=='redirect' and not fixed and q.startswith('https://atlas-redirect.invalid/'):return self.reply(302,'',[('Location',q)])
        if kind=='cache':
            key=p.query;marker=self.headers.get('X-Forwarded-Host','');cache=self.server.cache
            if self.headers.get('Cache-Control','').startswith('no-cache'):cache.pop(key,None)
            if marker and not fixed:cache[key]=marker
            return self.reply(200,cache.get(key,'ordinary fixed response'))
        if kind=='fetch':
            if not fixed and q.startswith(self.server.callback_origin+'/c/'):
                with urllib.request.urlopen(q,timeout=2) as response:response.read(8192)
            return self.reply(200,'ordinary response')
        return self.reply(200,'ordinary fixed response')
    def do_POST(self):
        fixed='/fixed/' in self.path;raw=self.rfile.read(int(self.headers.get('Content-Length','0'))).decode()
        if self.path.endswith('/xml'):
            if fixed and '<!DOCTYPE' in raw:return self.reply(400,'DOCTYPE disabled')
            external=re.search(r'SYSTEM "([^"]+)"',raw)
            if external:
                if external[1].startswith(self.server.callback_origin+'/c/'):
                    with urllib.request.urlopen(external[1],timeout=2) as response:response.read(8192)
                return self.reply(200,'received XML')
            try:return self.reply(200,ET.fromstring(raw).text or '')
            except ET.ParseError:return self.reply(400,'invalid XML')
        if self.path.endswith('/csrf'):
            if fixed and ('csrf=' not in raw or self.headers.get('Origin')=='https://atlas-csrf.invalid'):return self.reply(403,'token rejected')
            self.server.mutations+=1;return self.reply(200,MARKER)
        return self.reply(200,'ordinary response')


class FamilyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=TEMP);root=Path(self.temp.name);(root/'webroot').mkdir();(root/'canary.txt').write_text(MARKER,encoding='utf-8');self.store=Store(root/'atlas.sqlite3');self.workspace=self.store.create('Broad synthetic','Owned temporary canaries');self.tools=WebTools(self.store,8765);self.server=ThreadingHTTPServer(('127.0.0.1',0),BroadFixture);self.server.root=root;self.server.cache={};self.server.mutations=0;self.server.callback_origin='';threading.Thread(target=self.server.serve_forever,daemon=True).start();self.origin=f'http://127.0.0.1:{self.server.server_address[1]}';self.config={'url':self.origin+'/vuln/boolean?q=base','authorized':True,'max_requests':40,'max_seconds':30,'delay_ms':250,'max_depth':0,'active_audit':True}
    def tearDown(self):self.tools.shutdown();self.server.shutdown();self.server.server_close();self.temp.cleanup()
    def run_scan(self,**change):
        run=self.tools.start(self.workspace['id'],'scanner',{**self.config,**change})
        for _ in range(600):
            row=next(r for r in self.store.web_runs(self.workspace['id']) if r['id']==run['id'])
            if row['state'] not in ('queued','running'):return row
            time.sleep(.05)
        self.fail('Canary scan did not finish')
    def test_true_false_and_error_family_positive_fixed_controls(self):
        for endpoint,check in [('boolean','sql-boolean'),('nosql','nosql-error'),('ldap','ldap-error'),('xpath','xpath-error'),('command','command-arithmetic')]:
            positive=self.run_scan(url=self.origin+'/vuln/'+endpoint+'?q=base',checks=[check]);self.assertEqual(positive['state'],'completed');self.assertEqual(positive['findings'],1,check)
            negative=self.run_scan(url=self.origin+'/fixed/'+endpoint+'?q=base',checks=[check]);self.assertEqual(negative['findings'],0,check)
        self.assertTrue(all(f['validation']=='scanner-reported' for f in self.store.get(self.workspace['id'])['findings']))
    def test_actual_file_canary_redirect_and_isolated_cache_cleanup(self):
        for endpoint,check,extra in [('file','file-canary',{'canary_path':'../canary.txt','canary_marker':MARKER}),('redirect','open-redirect',{}),('cache','cache-canary',{'canary_marker':MARKER})]:
            url=self.origin+'/vuln/'+endpoint+'?q=base';positive=self.run_scan(url=url,checks=[check],canary_url=url,**extra);self.assertEqual(positive['findings'],1,check)
            url=self.origin+'/fixed/'+endpoint+'?q=base';negative=self.run_scan(url=url,checks=[check],canary_url=url,**extra);self.assertEqual(negative['findings'],0,check)
        self.assertEqual(self.server.cache,{})
    def test_xml_internal_external_and_http_oob_actual_callbacks(self):
        receiver=OOBReceiver(self.tools,self.workspace['id'],{**self.config,'oob_port':port(),'dns_port':port()});self.tools.receivers[receiver.run['id']]=receiver;self.server.callback_origin=receiver.origin
        for endpoint in ('vuln','fixed'):
            request={'url':self.origin+'/'+endpoint+'/xml','method':'POST','headers':[{'name':'Content-Type','value':'application/xml'}],'body':'<atlas>baseline</atlas>'};result=self.run_scan(url=self.origin+'/empty',checks=['xml-entity','oob-xml'],audit_requests=[request],oob_id=receiver.run['id']);self.assertEqual(result['state'],'completed');self.assertEqual(result['findings'],2 if endpoint=='vuln' else 0)
        result=self.run_scan(url=self.origin+'/vuln/fetch?q=base',checks=['oob-http'],oob_id=receiver.run['id']);self.assertEqual(result['state'],'completed');workspace=self.store.get(self.workspace['id']);self.assertEqual(len([f for f in workspace['findings'] if f['external_id']=='atlas-oob-http']),2);self.assertGreaterEqual(receiver.count,2)
    def test_stateful_csrf_canary_positive_and_fixed(self):
        for endpoint,expected in [('vuln',1),('fixed',0)]:
            url=self.origin+'/'+endpoint+'/csrf';request={'url':url,'method':'POST','headers':[{'name':'Content-Type','value':'application/x-www-form-urlencoded'}],'body':'value=fixture&csrf=fixture-token'};result=self.run_scan(url=self.origin+'/empty',checks=['csrf-canary'],canary_url=url,canary_marker=MARKER,audit_requests=[request]);self.assertEqual(result['findings'],expected)


if __name__=='__main__':unittest.main()
