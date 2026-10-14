"""Native pinned RFC6455 text/binary messages, replay and live proxy interception."""
import base64
import copy
import hashlib
import socket
import ssl
import threading
import time
import uuid
import select
from urllib.parse import urlsplit,urlunsplit

from .importers import ImportProblem
from .store import now
from .web_evidence import safe_url,web_url
from .web_transport import Scope,fetch,request_headers

MAX_MESSAGE=65536


def http_url(url):
    p=urlsplit(url)
    if p.scheme not in ('ws','wss'):raise ImportProblem('WebSocket URL must use ws:// or wss://.')
    result=urlunsplit(('https' if p.scheme=='wss' else 'http',p.netloc,p.path,p.query,''));web_url(result);return result


def library():
    try:
        import wsproto
        from wsproto import events
        return wsproto,events
    except ImportError:raise ImportProblem('WebSockets require requirements-protocols.txt in Atlas’s Python.') from None


class SocketClient:
    def __init__(self,scope,url,headers=None,timeout=5):
        wsproto,events=library();self.events=events;self.url=http_url(url);origin=scope.check(self.url);_,path,query,host,port=web_url(self.url);self.scope=scope;self.ws=wsproto.WSConnection(wsproto.ConnectionType.CLIENT);self.sock=None;self.lock=threading.RLock();self.buffer=[];self.closed=False;self.total=0;started=time.monotonic();self.deadline=started+300
        outbound=request_headers(headers or []);protocols=next((v.split(',') for k,v in outbound.items() if k.lower()=='sec-websocket-protocol'),[]);extra=[(k.encode(),v.encode()) for k,v in outbound.items() if k.lower() not in ('connection','accept-encoding','sec-websocket-key','sec-websocket-version','sec-websocket-extensions','sec-websocket-protocol')]
        self.sock=socket.create_connection((scope.pins[origin][0],port),timeout)
        try:
            if origin.startswith('https:'):self.sock=scope.tls.wrap_socket(self.sock,server_hostname=host)
            self.sock.settimeout(timeout);request=self.ws.send(events.Request(host=urlsplit(self.url).netloc,target=path+('?' + query if query else ''),extra_headers=extra,subprotocols=[p.strip() for p in protocols]));self.sock.sendall(request);accepted=None
            while accepted is None:
                if time.monotonic()-started>timeout:raise ImportProblem('WebSocket handshake timed out.')
                data=self.sock.recv(65536);self.total+=len(data)
                if not data or self.total>131072:raise ImportProblem('WebSocket handshake closed or exceeded limits.')
                self.ws.receive_data(data)
                for event in self.ws.events():
                    if isinstance(event,events.AcceptConnection):accepted=event
                    elif isinstance(event,(events.RejectConnection,events.CloseConnection)):raise ImportProblem('WebSocket handshake rejected; no protocol fallback.')
                    else:self.buffer.append(event)
            self.handshake={'id':uuid.uuid4().hex,'url':self.url,'captured_at':now(),'request':{'method':'GET','url':self.url,'headers':[{'name':k,'value':v} for k,v in outbound.items()],'body':''},'response':{'status':101,'headers':[{'name':k.decode(),'value':v.decode(errors='replace')} for k,v in accepted.extra_headers],'body':'','bytes':0,'body_sha256':hashlib.sha256(b'').hexdigest()},'connected_address':scope.pins[origin][0],'http_version':'HTTP/1.1 WebSocket Upgrade','upstream_tls':self.sock.version() if isinstance(self.sock,ssl.SSLSocket) else None,'parameters':[],'links':[]}
            if isinstance(self.sock,ssl.SSLSocket):self.handshake['peer_certificate_sha256']=hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            self.sock.settimeout(.25)
            self.subprotocol=accepted.subprotocol
        except Exception:self.sock.close();raise
    def send(self,data,binary=False):
        raw=data if binary else data.encode('utf-8')
        if len(raw)>MAX_MESSAGE:raise ImportProblem('WebSocket message exceeds 64 KiB.')
        with self.lock:
            if self.closed:raise ImportProblem('WebSocket is closed.')
            wire=self.ws.send(self.events.BytesMessage(data=raw) if binary else self.events.TextMessage(data=data));self.sock.sendall(wire)
    def receive(self):
        parts=[];size=0;binary=False
        while not self.closed:
            if time.monotonic()>=self.deadline:raise ImportProblem('WebSocket connection time limit reached.')
            with self.lock:events=self.buffer;self.buffer=[]
            if not events:
                try:data=self.sock.recv(65536)
                except socket.timeout:
                    if parts:continue
                    return None
                if not data:self.closed=True;return {'closed':True}
                self.total+=len(data)
                if self.total>4*1024*1024:raise ImportProblem('WebSocket connection wire limit exceeded.')
                with self.lock:self.ws.receive_data(data);events=list(self.ws.events())
            for event in events:
                if isinstance(event,self.events.Ping):
                    with self.lock:self.sock.sendall(self.ws.send(event.response()))
                elif isinstance(event,self.events.CloseConnection):self.closed=True;return {'closed':True,'code':event.code}
                elif isinstance(event,(self.events.TextMessage,self.events.BytesMessage)):
                    binary=isinstance(event,self.events.BytesMessage);parts.append(event.data);size+=len(event.data) if binary else len(event.data.encode())
                    if size>MAX_MESSAGE:raise ImportProblem('WebSocket fragmented message exceeds 64 KiB.')
                    if event.message_finished:
                        remaining=events[events.index(event)+1:]
                        with self.lock:self.buffer=remaining+self.buffer
                        return {'binary':binary,'data':b''.join(parts) if binary else ''.join(parts)}
        return {'closed':True}
    def close(self):
        with self.lock:
            if self.sock:
                try:self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.sock.close();self.sock=None
            self.closed=True
            self.buffer.clear()
            if hasattr(self,'handshake'):self.handshake.clear()


def message_event(url,direction,data,binary,connection_id,original=None):
    raw=data if binary else data.encode();value=base64.b64encode(raw).decode() if binary else data
    return {'id':uuid.uuid4().hex,'url':url,'captured_at':now(),'request':{},'parameters':[],'links':[],'websocket':{'connection_id':connection_id,'direction':direction,'opcode':'binary' if binary else 'text','bytes':len(raw),'message_sha256':hashlib.sha256(raw).hexdigest(),'encoding':'base64' if binary else 'UTF-8','body':value,'original_message_sha256':original,'limit':'RFC6455 message evidence; not a new HTTP response or proof of message authorization.'}}


class WebSocketSession:
    def __init__(self,tools,workspace,config):
        from .web_tools import bounded_int
        from .web_auth import AuthSession
        self.tools=tools;self.workspace=workspace;self.config=tools.session_config(workspace,config);self.scope=Scope(self.config,tools.port);self.scope.protocol='http1';tools.block_controls(self.scope);self.url=http_url(config.get('ws_url',''));self.scope.check(self.url);self.lock=threading.RLock();self.closed=False;self.messages=[];self.saved_messages={};self.count=0;self.message_count=0;self.imports=[];self.auth=None;self.client=None;self.error=None
        self.limit=bounded_int(config,'max_requests',100,1,200);self.seconds=bounded_int(config,'max_seconds',60,1,300);self.started=time.monotonic()
        self.findings=0
        if self.config.get('auth'):self.auth=AuthSession(self.scope,self.config['auth'])
        self.http_requests=0
        self.run=tools.store.start_web_run(workspace,'websocket',{'url':safe_url(self.url),'scope':self.scope.summary(),'max_operations':self.limit,'max_seconds':self.seconds,'authenticated_handshake':bool(self.auth),'retention':'raw recent messages transient until channel closes; selected evidence redaction applies'})
        tools.store.update_web_run(workspace,self.run['id'],state='running')
        def budget():
            if self.count>=self.limit or time.monotonic()-self.started>=self.seconds:raise ImportProblem('WebSocket authentication/handshake exhausted the shared budget.')
        try:
            def request(url,method='GET',headers=None,body='',anonymous=False,purpose='session verification'):
                budget()
                if self.count:time.sleep(.25);budget()
                event=fetch(self.scope,url,method,[] if anonymous else self.auth.headers(url,headers),body,timeout=min(5,max(.1,self.seconds-(time.monotonic()-self.started))));self.count+=1;self.http_requests=self.count
                if not anonymous:self.auth.absorb(event)
                event['authentication']={'mode':'anonymous control' if anonymous else 'session credentials','session_verified':self.auth.verified,'purpose':purpose,'generation':self.auth.generation}
                self.imports.append(tools.capture(workspace,self.auth.scrub(event),'web-workbench',{**config,'retain_body':False}));return event
            if self.auth:
                if self.auth.valid(request(self.auth.guard,anonymous=True)):raise ImportProblem('Session marker is visible anonymously.')
                self.auth.login(request)
            budget();self.count+=1;self.http_requests=self.count
            self.client=SocketClient(self.scope,config['ws_url'],self.auth.headers(self.url,config.get('headers',[])) if self.auth else config.get('headers',[]),timeout=min(5,max(.1,self.seconds-(time.monotonic()-self.started))))
            self.client.deadline=self.started+self.seconds
            if self.auth:self.client.handshake['authentication']={'mode':'verified handshake session','session_verified':True,'purpose':'WebSocket handshake; message authorization remains unverified','generation':self.auth.generation}
            self.imports.append(tools.capture(workspace,self.auth.scrub(self.client.handshake) if self.auth else self.client.handshake,'web-workbench',config))
            tools.store.update_web_run(workspace,self.run['id'],state='running',requests=self.http_requests,import_ids=self.imports)
        except Exception:
            self.closed=True
            if self.client:self.client.close()
            event={'id':uuid.uuid4().hex,'url':self.url,'captured_at':now(),'request':{'method':'GET','url':self.url,'headers':[]},'parameters':[],'links':[],'error':'WebSocket session verification, handshake, dependency or certificate failed; no anonymous/protocol fallback.'}
            self.imports.append(tools.capture(workspace,self.auth.scrub(event) if self.auth else event,'web-workbench',{**config,'retain_body':False}))
            tools.store.update_web_run(workspace,self.run['id'],state='failed',requests=self.http_requests,import_ids=self.imports,reason=event['error'],ended_at=now())
            if self.auth:self.auth.clear()
            self.config.pop('auth',None);self.config.pop('headers',None)
            raise ImportProblem('WebSocket session/handshake failed; failure metadata saved. Check the protected session marker, scope, upstream certificate, dependency and server support.') from None
        threading.Thread(target=self._read,daemon=True).start()
    def capture(self,direction,data,binary):
        with self.lock:
            if self.closed or self.count>=self.limit or time.monotonic()-self.started>=self.seconds:raise ImportProblem('WebSocket message/time limit reached.')
            event=message_event(self.url,direction,data,binary,self.run['id']);self.count+=1;self.message_count+=1;self.messages.append({'id':event['id'],**event['websocket']});self.messages=self.messages[-20:];saved=self.auth.scrub(event) if self.auth else event;self.saved_messages[event['id']]=saved
            self.saved_messages={row['id']:self.saved_messages[row['id']] for row in self.messages}
            self.imports.append(self.tools.capture(self.workspace,saved,'web-workbench',self.config));self.tools.store.update_web_run(self.workspace,self.run['id'],requests=self.http_requests,message_count=self.message_count,import_ids=self.imports)
    def send(self,value,binary=False):
        if not isinstance(value,str) or len(value)>90000:raise ImportProblem('Supply a bounded text or Base64 message.')
        try:data=base64.b64decode(value,validate=True) if binary else value
        except ValueError:raise ImportProblem('Invalid Base64 message.') from None
        with self.lock:
            if self.closed or self.count>=self.limit:raise ImportProblem('WebSocket is closed or at its limit.')
            self.client.send(data,binary);self.capture('to server',data,binary)
        return self.status()
    def _read(self):
        try:
            while not self.closed and self.count<self.limit and time.monotonic()-self.started<self.seconds:
                result=self.client.receive()
                if result and result.get('closed'):self.close('Peer closed WebSocket');break
                if result:self.capture('from server',result['data'],result['binary'])
        except Exception:
            if not self.closed:self.error='WebSocket closed, timed out or exceeded protocol/message limits'
        finally:self.close('WebSocket ended or reached its message/time limit')
    def status(self):
        with self.lock:return {'id':self.run['id'],'state':'stopped' if self.closed else 'running','messages':copy.deepcopy(self.messages),'message_count':self.message_count,'http_requests':self.http_requests,'findings':self.findings,'error':self.error}
    def finding(self,message_id,title,severity,detail):
        from .importers import clean
        with self.lock:
            row=next((r for r in self.messages if r['id']==message_id),None)
            if not row:raise ImportProblem('Choose a recent message from this WebSocket session.')
            if not isinstance(title,str) or not 1<=len(title)<=150 or severity not in ('info','low','medium','high','critical') or not isinstance(detail,str) or not 1<=len(detail)<=3000:raise ImportProblem('Supply a bounded finding title, severity and evidence explanation.')
            event=copy.deepcopy(self.saved_messages[row['id']]);event['id']=uuid.uuid4().hex;event['source_capture_id']=row['id'];event['test']={'baseline_event_id':row['id'],'control_event_ids':[],'run_id':self.run['id'],'scope':'Operator assertion from a WebSocket capture; review validation separately'};event['issue']={'name':clean(title),'type':'atlas-websocket-operator','severity':severity,'confidence':'operator-supplied assertion','detail':clean(detail)+' Source is an operator assertion attached to this message, not independently validated impact.'}
            imported=self.tools.capture(self.workspace,self.auth.scrub(event) if self.auth else event,'web-scanner',self.config);self.imports.append(imported);self.findings+=1
            self.tools.store.update_web_run(self.workspace,self.run['id'],findings=self.findings,import_ids=self.imports)
            return {'import_id':imported,'saved_directly':True}
    def close(self,reason='Operator stopped WebSocket'):
        with self.lock:
            if self.closed:return
            self.closed=True
            if self.client:self.client.close()
            if self.auth:self.auth.clear()
            self.config.pop('auth',None);self.config.pop('headers',None);self.messages.clear();self.saved_messages.clear()
            self.tools.store.update_web_run(self.workspace,self.run['id'],state='partial' if self.error or 'limit' in reason else 'stopped',reason=reason,ended_at=now(),message_count=self.message_count)


def relay(proxy,downstream,url,headers):
    """HTTP/1.1 Upgrade on the browser hop, independently verified pinned upstream."""
    wsproto,events=library();p=urlsplit(url);url=http_url(url) if p.scheme in ('ws','wss') else url;origin=proxy.scope.check(url)
    with proxy.lock:
        if proxy.closed or proxy.count>=proxy.limit:raise ImportProblem('Proxy request limit reached.')
        proxy.count+=1
    upstream=SocketClient(proxy.scope,url.replace('https:','wss:',1).replace('http:','ws:',1),headers);upstream.deadline=proxy.started+proxy.duration;server=wsproto.WSConnection(wsproto.ConnectionType.SERVER)
    target=(urlsplit(url).path or '/')+('?' + urlsplit(url).query if urlsplit(url).query else '');parsed=request_headers(headers)
    # Rebuild only the already parsed header block for the server-side state machine.
    original={h['name'].lower():h['value'] for h in headers};handshake='GET '+target+' HTTP/1.1\r\nHost: '+urlsplit(url).netloc+'\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
    for key in ('sec-websocket-key','sec-websocket-version','sec-websocket-protocol'):
        if key in original:handshake+=key+': '+original[key]+'\r\n'
    server.receive_data((handshake+'\r\n').encode());requests=list(server.events())
    if not any(isinstance(event,events.Request) for event in requests):upstream.close();raise ImportProblem('WebSocket client handshake was malformed.')
    downstream.sendall(server.send(events.AcceptConnection(subprotocol=upstream.subprotocol)));downstream.settimeout(.25);connection_id=uuid.uuid4().hex;parts=[];size=0;wire_total=0
    with proxy.lock:proxy.ws_connections.append((upstream,downstream))
    def save(event):
        imported=proxy.tools.capture(proxy.workspace,event,'web-browser' if proxy.config.get('browser_owned') else 'web-proxy',proxy.config)
        with proxy.lock:
            current=next(r for r in proxy.tools.store.web_runs(proxy.workspace) if r['id']==proxy.run['id']);proxy.tools.store.update_web_run(proxy.workspace,proxy.run['id'],requests=proxy.count,websocket_messages=proxy.ws_count,import_ids=current['import_ids']+[imported])
    save(upstream.handshake)
    def message(direction,data,binary):
        with proxy.lock:
            if proxy.closed or proxy.ws_count>=proxy.limit:raise ImportProblem('Proxy WebSocket message limit reached.')
            proxy.ws_count+=1;intercept=proxy.ws_intercept
        event=message_event(url,direction,data,binary,connection_id);event['websocket']['forwarded']=not intercept;save(event)
        if intercept:
            key=uuid.uuid4().hex;item={'phase':'websocket','request':{'url':url,'method':'WebSocket '+direction,'direction':direction,'body':base64.b64encode(data).decode() if binary else data,'binary':binary},'ready':threading.Event(),'action':'drop'}
            with proxy.lock:
                if len(proxy.pending)>=30:raise ImportProblem('Interception queue full.')
                proxy.pending[key]=item
            try:
                item['ready'].wait(30)
                if item['action']!='forward':return
                edit=item['edited'];binary=edit['binary'];data=base64.b64decode(edit['body'],validate=True) if binary else edit['body'];derived=message_event(url,direction,data,binary,connection_id,event['websocket']['message_sha256']);derived['source_capture_id']=event['id'];derived['websocket']['forwarded']=True;derived['interception']={'websocket_intercepted':True,'original_capture_id':event['id'],'limit':'Operator-forwarded application message; original received message retained separately.'};save(derived)
            finally:
                with proxy.lock:proxy.pending.pop(key,None)
        if direction=='to server':upstream.send(data,binary)
        else:downstream.sendall(server.send(events.BytesMessage(data=data) if binary else events.TextMessage(data=data)))
    try:
        while not proxy.closed and proxy.ws_count<proxy.limit and time.monotonic()-proxy.started<proxy.duration:
            ready=select.select([downstream,upstream.sock],[],[],.1)[0]
            if upstream.buffer or upstream.sock in ready or (isinstance(upstream.sock,ssl.SSLSocket) and upstream.sock.pending()):
                result=upstream.receive()
                if result and result.get('closed'):break
                if result:message('from server',result['data'],result['binary'])
            if downstream in ready or (isinstance(downstream,ssl.SSLSocket) and downstream.pending()):
                data=downstream.recv(65536);wire_total+=len(data)
                if not data:break
                if wire_total>4*1024*1024:raise ImportProblem('WebSocket client wire limit exceeded.')
                server.receive_data(data)
                for event in server.events():
                    if isinstance(event,events.Ping):downstream.sendall(server.send(event.response()))
                    elif isinstance(event,events.CloseConnection):return
                    elif isinstance(event,(events.TextMessage,events.BytesMessage)):
                        binary=isinstance(event,events.BytesMessage);parts.append(event.data);size+=len(event.data) if binary else len(event.data.encode())
                        if size>MAX_MESSAGE:raise ImportProblem('WebSocket client message exceeds 64 KiB.')
                        if event.message_finished:message('to server',b''.join(parts) if binary else ''.join(parts),binary);parts=[];size=0
    finally:
        upstream.close()
        with proxy.lock:
            if (upstream,downstream) in proxy.ws_connections:proxy.ws_connections.remove((upstream,downstream))
