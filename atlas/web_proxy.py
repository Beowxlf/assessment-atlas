"""Authenticated loopback HTTP/1.1 browser hop with scoped upstream HTTP/WS engines."""
import base64
import datetime as dt
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
from pathlib import Path
import secrets
import ssl
import threading
import time
import uuid
import copy

from .importers import ImportProblem
from .web_transport import Scope,fetch,METHODS
from .web_tools import bounded_int
from .store import now
from .lifecycle import TrackedRequests


class LocalCertificates:
    def __init__(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import hashes,serialization
            from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
        except ImportError:raise ImportProblem('HTTPS interception requires cryptography. Install requirements-web.txt with the Python used to start Atlas.') from None
        self.x509=x509;self.rsa=rsa;self.hashes=hashes;self.serialization=serialization;self.NameOID=NameOID;self.ExtendedKeyUsageOID=ExtendedKeyUsageOID
        self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Assessment Atlas isolated interception '+uuid.uuid4().hex[:8])])
        start=dt.datetime.now(dt.timezone.utc)
        # RFC 5280 issuer/key identifiers keep these ephemeral chains valid
        # under strict clients (including Python 3.13's default TLS policy).
        self.ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(start-dt.timedelta(minutes=5))
                 .not_valid_after(start+dt.timedelta(days=7))
                 .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
                 .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=None,decipher_only=None),critical=True)
                 .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),critical=False)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),critical=False)
                 .sign(self.key,hashes.SHA256()))
        self.pem=self.ca.public_bytes(serialization.Encoding.PEM).decode()
        self.fingerprint=self.ca.fingerprint(hashes.SHA256()).hex()
        spki=self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        self.spki=base64.b64encode(hashlib.sha256(spki).digest()).decode();self.cache={};self.lock=threading.Lock()

    def context(self,hostname,folder):
        with self.lock:
            if hostname in self.cache:return self.cache[hostname]
            x509=self.x509;serialization=self.serialization;key=self.rsa.generate_private_key(public_exponent=65537,key_size=2048);start=dt.datetime.now(dt.timezone.utc)
            try:san=x509.IPAddress(ipaddress.ip_address(hostname))
            except ValueError:san=x509.DNSName(hostname)
            certificate=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(self.NameOID.COMMON_NAME,hostname)]))
                         .issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                         .not_valid_before(start-dt.timedelta(minutes=5)).not_valid_after(start+dt.timedelta(days=1))
                         .add_extension(x509.SubjectAlternativeName([san]),critical=False)
                         .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
                         .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),critical=True)
                         .add_extension(x509.ExtendedKeyUsage([self.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
                         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
                         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),critical=False)
                         .sign(self.key,self.hashes.SHA256()))
            # The CA private key stays in process memory. Leaf key exists only until SSLContext loads it.
            path=folder/(uuid.uuid4().hex+'.pem')
            try:
                with path.open('xb') as f:f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())+certificate.public_bytes(serialization.Encoding.PEM)+self.ca.public_bytes(serialization.Encoding.PEM))
                path.chmod(0o600);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(path)
            finally:
                if path.exists():path.unlink()
            self.cache[hostname]=context;return context


class ProxyServer(TrackedRequests,ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,handler):
        self.slots=threading.BoundedSemaphore(16)
        super().__init__(address,handler)
    def process_request(self,request,client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request);return
        try:super().process_request(request,client_address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.slots.release()


class Proxy:
    def __init__(self,tools,workspace,config,review_config=None):
        self.tools=tools;self.workspace=workspace;self.config=config;self.scope=Scope(config,tools.port);self.certificates=LocalCertificates();self.lock=threading.RLock();self.pending={};self.closed=False;self.close_complete=threading.Event();self.count=0;self.rejected=0;self.errors=[];self.intercept=config.get('intercept') is True;self.token=secrets.token_urlsafe(32)
        proof=tools.bind_execution(workspace,self.scope,review_config or config,kind='browser' if config.get('browser_owned') else 'proxy')
        if proof:self.config={**config,'vantage':proof['host']['name']+' · '+proof['interface']}
        embedded=config.get('embedded') is True and config.get('browser_owned') is True
        self.limit=bounded_int(config,'max_requests',100,1,500 if embedded else 200);self.duration=bounded_int(config,'max_seconds',300,1,1800 if embedded else 300);port=bounded_int(config,'proxy_port',8877,1024,65535)
        self.intercept_response=config.get('intercept_response') is True
        self.ws_intercept=False;self.ws_connections=[];self.ws_count=0
        if port==tools.port:raise ImportProblem('Proxy port must differ from Atlas.')
        folder=tools.store.path.parent/'proxy-tls-volatile';folder.mkdir(exist_ok=True)
        if __import__('os').name=='nt':
            import getpass,subprocess
            try:subprocess.run(['icacls',str(folder),'/inheritance:r','/grant:r',getpass.getuser()+':(OI)(CI)F','SYSTEM:(OI)(CI)F','Administrators:(OI)(CI)F'],check=True,capture_output=True)
            except (OSError,subprocess.CalledProcessError):raise ImportProblem('Could not restrict temporary TLS-key directory access.') from None
        else:folder.chmod(0o700)
        self.folder=folder
        try:self.server=ProxyServer(('127.0.0.1',port),ProxyHandler)
        except OSError:raise ImportProblem('Proxy port is occupied; select a different loopback port.') from None
        self.server.daemon_threads=True;self.server.proxy=self;self.scope.forbidden_ports.add(port)
        self.run=tools.store.start_web_run(workspace,'browser' if config.get('browser_owned') else 'proxy',{'scope':self.scope.summary(),'port':port,'max_requests':self.limit,'max_seconds':self.duration,'capture_mode':'redacted' if config.get('retain_body') else 'metadata','CA_sha256':self.certificates.fingerprint})
        if proof:tools.store.update_web_run(workspace,self.run['id'],plan={**self.run['plan'],'execution_context':proof})
        self.started=time.monotonic();tools.store.update_web_run(workspace,self.run['id'],state='running')
        self.threads=[threading.Thread(target=self.server.serve_forever,daemon=True),threading.Thread(target=self._deadline,daemon=True)]
        for thread in self.threads:thread.start()

    def _deadline(self):
        while not self.closed and time.monotonic()-self.started<self.duration:
            try:self.scope.check_execution()
            except ImportProblem:
                self.errors.append('Execution route/session context changed; completed evidence retained.');self.close('Execution context lost; incomplete coverage');return
            time.sleep(.25)
        if not self.closed:self.close('Time limit reached')

    def status(self,include_token=False):
        with self.lock:
            result={'id':self.run['id'],'state':'stopped' if self.closed else 'running','port':self.server.server_address[1],'requests':self.count,'intercept':self.intercept,'intercept_response':self.intercept_response,'CA_sha256':self.certificates.fingerprint,'pending':[{'id':key,'phase':value.get('phase','request'),**value['request']} for key,value in self.pending.items() if not value['ready'].is_set()],'scope':self.scope.summary()}
            result.update(websocket_intercept=self.ws_intercept,websocket_messages=self.ws_count,websocket_connections=len(self.ws_connections))
        if include_token:result.update(username='atlas',password=self.token,ca_pem=self.certificates.pem,ca_spki_sha256=self.certificates.spki)
        return result

    def decide(self,item_id,action,changes):
        if not isinstance(changes,dict):raise ImportProblem('Request edits must be an object.')
        with self.lock:
            item=self.pending.get(item_id)
            if not item or item['ready'].is_set():raise ImportProblem('Intercepted request is no longer pending.')
            if action not in ('forward','drop'):raise ImportProblem('Choose forward or drop.')
            request=item['request']
            if action=='forward':
                if item.get('phase')=='websocket':
                    body=changes.get('body',request['body']);binary=changes.get('binary',request['binary'])
                    if not isinstance(body,str) or not isinstance(binary,bool) or len(body)>90000:raise ImportProblem('Invalid bounded WebSocket edit.')
                    try:raw=base64.b64decode(body,validate=True) if binary else body.encode()
                    except ValueError:raise ImportProblem('Invalid Base64 frame edit.') from None
                    if len(raw)>65536:raise ImportProblem('WebSocket message exceeds 64 KiB.')
                    item['edited']={**request,'body':body,'binary':binary};item['action']=action;item['ready'].set();return
                if item.get('phase')=='response':
                    status=changes.get('status',request['status']);body=changes.get('body',request['body']);headers=changes.get('headers',request['headers'])
                    from .web_transport import request_headers
                    if isinstance(status,bool) or not isinstance(status,int) or not 200<=status<=599 or not isinstance(body,str) or len(body.encode())>16384:raise ImportProblem('Response edit needs a 200–599 status and UTF-8 body up to 16 KiB.')
                    if status in (204,205,304) and body:raise ImportProblem('This response status cannot contain a body.')
                    validated=request_headers(headers)
                    validated=[{'name':k,'value':v} for k,v in validated.items() if k.lower() not in ('connection','accept-encoding','user-agent','content-encoding')]
                    item['edited']={**request,'status':status,'headers':validated,'body':body};item['action']=action;item['ready'].set();return
                method=changes.get('method',request['method']);body=changes.get('body',request['body']);headers=changes.get('headers',request['headers'])
                from .web_transport import request_headers
                if method not in METHODS or not isinstance(body,str) or len(body.encode())>16384:raise ImportProblem('Invalid bounded request edit.')
                request_headers(headers);item['edited']={**request,'method':method,'headers':headers,'body':body}
            item['action']=action;item['ready'].set()

    def exchange(self,url,method,headers,body):
        self.scope.check(url)
        with self.lock:
            if self.closed or self.count>=self.limit or time.monotonic()-self.started>=self.duration:raise ImportProblem('Proxy stopped or request/time limit reached.')
            self.count+=1;intercept=self.intercept
        original_hash=hashlib.sha256((method+'\n'+url+'\n'+repr(headers)+'\n'+body).encode()).hexdigest()
        if intercept:
            key=uuid.uuid4().hex;item={'request':{'url':url,'method':method,'headers':headers,'body':body},'ready':threading.Event(),'action':'drop'}
            with self.lock:
                if len(self.pending)>=30:raise ImportProblem('Interception queue full.')
                self.pending[key]=item
            try:
                item['ready'].wait(30)
                if item['action']!='forward':
                    self.tools.capture(self.workspace,{'id':key,'url':url,'captured_at':now(),'request':item['request'],'error':'Request dropped or interception timed out'},'web-proxy',self.config)
                    raise ImportProblem('Request dropped or interception timed out.')
                edited=item['edited'];method=edited['method'];headers=edited['headers'];body=edited['body']
            finally:
                with self.lock:self.pending.pop(key,None)
        event,raw=fetch(self.scope,url,method,headers,body,wire=True)
        event['interception']={'request_intercepted':intercept,'original_request_fields_sha256':original_hash,'hash_scope':'method, URL, decoded header list and body fields; not original wire bytes','limit':'Original request not retained; edited request passed scope/framing checks.'}
        source='web-browser' if self.config.get('browser_owned') else 'web-proxy'
        imported=self.tools.capture(self.workspace,event,source,self.config)
        with self.lock:
            current=next(r for r in self.tools.store.web_runs(self.workspace) if r['id']==self.run['id'])
            self.tools.store.update_web_run(self.workspace,self.run['id'],requests=self.count,import_ids=current['import_ids']+[imported])
        imported_ids=[]
        content_type=next((h['value'] for h in event.get('response',{}).get('headers',[]) if h['name'].lower()=='content-type'),'')
        encoding=next((h['value'] for h in event.get('response',{}).get('headers',[]) if h['name'].lower()=='content-encoding'),'identity')
        if self.intercept_response and encoding.lower()=='identity' and not event.get('error') and not event['response']['truncated'] and len(raw)<=16384 and any(kind in content_type for kind in ('text/','json','xml')):
            try:raw.decode('utf-8',errors='strict')
            except UnicodeError:pass
            else:
                key=uuid.uuid4().hex;item={'phase':'response','request':{'url':url,'method':method,**copy.deepcopy(event['response'])},'ready':threading.Event(),'action':'drop'}
                with self.lock:
                    if len(self.pending)>=30:raise ImportProblem('Interception queue full.')
                    self.pending[key]=item
                try:
                    item['ready'].wait(30)
                    if item['action']!='forward':raise ImportProblem('Response dropped or interception timed out; upstream capture retained.')
                    edited=item['edited'];derived=copy.deepcopy(event);derived['id']=key;derived['source_capture_id']=event['id'];derived['response']={**event['response'],**{k:edited[k] for k in ('status','headers','body')}};raw=edited['body'].encode()
                    derived['response'].update(bytes=len(raw),body_sha256=hashlib.sha256(raw).hexdigest(),digest_scope='operator-edited UTF-8 response body')
                    derived['interception']={**event['interception'],'response_intercepted':True,'upstream_response_event_id':event['id'],'upstream_response_body_sha256':event['response']['body_sha256'],'limit':'Operator-edited downstream response; not an upstream application behavior or additional target request.'}
                    imported_ids.append(self.tools.capture(self.workspace,derived,source,self.config));event=derived
                finally:
                    with self.lock:self.pending.pop(key,None)
        with self.lock:
            current=next(r for r in self.tools.store.web_runs(self.workspace) if r['id']==self.run['id']);imports=current['import_ids']+imported_ids
            self.tools.store.update_web_run(self.workspace,self.run['id'],requests=self.count,import_ids=imports)
        if event.get('error') or event.get('response',{}).get('truncated'):raise ImportProblem('Upstream failed or exceeded 2 MiB; bounded capture retained.')
        return event,raw

    def reject(self):
        with self.lock:
            if self.closed:return
            self.rejected+=1;self.errors.append('Request rejected, dropped, failed or exceeded a scope/framing/size limit')
            self.tools.store.update_web_run(self.workspace,self.run['id'],rejected_requests=self.rejected,errors=self.errors[-100:])

    def close(self,reason='Operator stopped proxy'):
        with self.lock:
            if self.closed:return
            self.closed=True
            for item in self.pending.values():item['ready'].set()
            for client,downstream in list(self.ws_connections):
                client.close()
                try:downstream.shutdown(__import__('socket').SHUT_RDWR)
                except OSError:pass
        try:
            self.server.shutdown();self.server.server_close()
            state='failed' if 'startup failed' in reason.lower() else 'partial' if self.errors or 'limit' in reason.lower() else 'stopped'
            self.tools.store.update_web_run(self.workspace,self.run['id'],state=state,ended_at=now(),reason=reason,requests=self.count,errors=self.errors[-100:],rejected_requests=self.rejected)
            self.certificates.cache.clear();self.certificates.key=None
        finally:self.close_complete.set()

    def wait_closed(self):
        # Separate drain from close(): deadline/browser/request threads may
        # initiate closure themselves and must never join one another there.
        self.close_complete.wait()
        for thread in self.threads:
            if thread is not threading.current_thread():thread.join()
        self.server.wait_requests()


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*_):pass
    def setup(self):
        super().setup();self.connection.settimeout(10)
    def finish(self):
        try:super().finish()
        finally:
            if getattr(self,'tunnel_authenticated',False):self.connection.close()
    def authenticated(self):
        expected='Basic '+base64.b64encode(('atlas:'+self.server.proxy.token).encode()).decode()
        if secrets.compare_digest(self.headers.get('Proxy-Authorization',''),expected):return True
        self.send_response(407);self.send_header('Proxy-Authenticate','Basic realm="Assessment Atlas scoped proxy"');self.send_header('Content-Length','0');self.send_header('Connection','close');self.end_headers();self.close_connection=True;return False
    def fail(self,text,status=502):
        self.server.proxy.reject()
        raw=text.encode('utf-8');self.send_response(status);self.send_header('Content-Type','text/plain');self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers();self.wfile.write(raw);self.close_connection=True
    def do_CONNECT(self):
        if not self.authenticated():return
        proxy=self.server.proxy
        try:
            url='https://'+self.path+'/'
            from .web_evidence import web_url
            origin,_,_,hostname,_=web_url(url)
            if origin not in proxy.scope.origins:raise ImportProblem('CONNECT origin is outside scope.')
            proxy.scope.check(origin+proxy.scope.origins[origin]);context=proxy.certificates.context(hostname,proxy.folder)
            self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n');self.wfile.flush()
            self.connection.settimeout(5);self.connection=context.wrap_socket(self.connection,server_side=True);self.rfile=self.connection.makefile('rb');self.wfile=self.connection.makefile('wb');self.tunnel_origin='https://'+self.path;self.tunnel_authenticated=True;self.connection.settimeout(40)
            self.handle_one_request();self.close_connection=True
        except (ImportProblem,OSError,ValueError):self.close_connection=True
    def exchange(self):
        if not getattr(self,'tunnel_authenticated',False) and not self.authenticated():return
        try:
            if self.headers.get('Upgrade','').lower()=='websocket':
                from .web_socket import relay
                url=(self.tunnel_origin+self.path) if hasattr(self,'tunnel_origin') else self.path
                relay(self.server.proxy,self.connection,url,[{'name':k,'value':v} for k,v in self.headers.items() if k.lower()!='proxy-authorization']);self.close_connection=True;return
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))>1:raise ImportProblem('Chunked or duplicate-length requests are not supported.')
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=16384:raise ImportProblem('Request body exceeds 16 KiB.')
            self.connection.settimeout(10);body=self.rfile.read(length).decode('utf-8')
            url=(self.tunnel_origin+self.path) if hasattr(self,'tunnel_origin') else self.path
            headers=[{'name':k,'value':v} for k,v in self.headers.items() if k.lower()!='proxy-authorization']
            event,raw=self.server.proxy.exchange(url,self.command,headers,body)
            self.send_response(event['response']['status'])
            for header in event['response']['headers']:
                if header['name'].lower() not in ('content-length','transfer-encoding','connection','keep-alive','proxy-authenticate'):self.send_header(header['name'],header['value'])
            self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers()
            if self.command!='HEAD':self.wfile.write(raw)
            self.close_connection=True
        except (ImportProblem,ValueError,UnicodeError,OSError) as exc:
            try:self.fail(str(exc)[:200] if isinstance(exc,ImportProblem) else 'Malformed request or connection failed')
            except OSError:pass
    do_GET=exchange;do_POST=exchange;do_HEAD=exchange;do_PUT=exchange;do_PATCH=exchange;do_DELETE=exchange;do_OPTIONS=exchange
