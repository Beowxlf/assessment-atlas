"""Owner-controlled bounded HTTP/DNS callback receiver and assessment correlation."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import re
import secrets
import socketserver
import struct
import threading
import time
import uuid

from .importers import ImportProblem
from .store import now
from .web_evidence import safe_url,web_url


class OOBReceiver:
    def __init__(self,tools,workspace,config):
        from .web_tools import bounded_int
        if config.get('authorized') is not True:raise ImportProblem('Confirm authority before starting an interaction receiver.')
        bind=config.get('bind_address','127.0.0.1')
        try:ip=ipaddress.ip_address(bind)
        except ValueError:raise ImportProblem('Interaction bind address must be a local numeric IPv4 address.') from None
        if ip.version!=4 or ip.is_multicast or ip.is_unspecified or ip.is_link_local:raise ImportProblem('Use an explicit local IPv4 interface; wildcard/metadata/multicast binding is not supported.')
        if not ip.is_loopback and config.get('allow_remote_listener') is not True:raise ImportProblem('Explicitly enable remote callbacks for this selected local interface.')
        self.tools=tools;self.workspace=workspace;self.lock=threading.RLock();self.tokens={};self.interactions=[];self.totals={};self.closed=False;self.started=time.monotonic();self.count=0;self.seconds=bounded_int(config,'max_seconds',300,1,300);self.limit=bounded_int(config,'max_requests',100,1,200);self.config=copy.deepcopy(config)
        port=bounded_int(config,'oob_port',8879,1024,65535);dns_port=bounded_int(config,'dns_port',5353,1,65535)
        if port==tools.port or dns_port==tools.port or dns_port==port:raise ImportProblem('Interaction ports must differ from control and each other.')
        domain=config.get('dns_domain','atlas.test')
        if not isinstance(domain,str):raise ImportProblem('Invalid owner-controlled DNS suffix.')
        domain=domain.lower().strip('.')
        if len(domain)>200 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in domain.split('.')):raise ImportProblem('Invalid owner-controlled DNS suffix.')
        self.domain=domain
        self.origin='http://'+bind+':'+str(port);advertised=config.get('callback_origin','')
        if advertised:
            origin,path,query,_,_=web_url(advertised)
            if path!='/' or query:raise ImportProblem('Advertised callback URL must be an exact owner-controlled origin.')
            if origin!=self.origin and config.get('allow_remote_listener') is not True:raise ImportProblem('Explicitly authorize an owner-controlled advertised receiver origin.')
            self.origin=origin
        try:self.http=HTTPReceiver((bind,port),HTTPHandler);self.dns=DNSReceiver((bind,dns_port),DNSHandler)
        except OSError:
            if hasattr(self,'http'):self.http.server_close()
            raise ImportProblem('Interaction listener bind failed; select unused ports on a local interface.') from None
        self.http.owner=self;self.http.daemon_threads=True;self.dns.owner=self
        self.run=tools.store.start_web_run(workspace,'oob-listener',{'bind_address':bind,'callback_origin':self.origin,'dns_suffix':domain,'dns_port':dns_port,'max_seconds':self.seconds,'max_interactions':self.limit,'limit':'HTTP/DNS receiver only; remote reachability, DNS delegation and TLS reverse proxy are operator-configured, never auto-published.'})
        tools.store.update_web_run(workspace,self.run['id'],state='running')
        threading.Thread(target=self.http.serve_forever,daemon=True).start();threading.Thread(target=self.dns.serve_forever,daemon=True).start();threading.Thread(target=self._deadline,daemon=True).start()
    def allocate(self,url,parameter='',baseline_id=None,run_id=None):
        web_url(url)
        with self.lock:
            if self.closed or len(self.tokens)>=100:raise ImportProblem('Interaction receiver stopped or token limit reached.')
            token=secrets.token_hex(24);reference=uuid.uuid4().hex;self.tokens[token]={'target':url,'parameter':parameter,'baseline_event_id':baseline_id,'run_id':run_id,'id':reference,'bound_capture_id':None,'expires':self.started+self.seconds,'reported_protocols':set()}
        return {'id':reference,'callback_url':self.origin+'/c/'+token,'dns_name':token+'.'+self.domain,'dns_port':self.dns.server_address[1]}
    def bind_capture(self,reference,event):
        with self.lock:
            row=next((r for r in self.tokens.values() if r['id']==reference),None)
            if not row:raise ImportProblem('Interaction token not found.')
            row['bound_capture_id']=event['id']
            binding={'id':uuid.uuid4().hex,'url':row['target'],'captured_at':now(),'request':{},'parameters':[],'links':[],'out_of_band':{'correlation_id':reference,'probe_capture_id':event['id'],'baseline_event_id':row['baseline_event_id'],'run_id':row['run_id'],'role':'issued probe binding','limit':'Correlates already retained callbacks/probe evidence without rewriting earlier observations.'}}
            imported=self.tools.capture(self.workspace,binding,'web-scanner',{**self.config,'retain_body':False});current=next(r for r in self.tools.store.web_runs(self.workspace) if r['id']==self.run['id']);self.tools.store.update_web_run(self.workspace,self.run['id'],import_ids=current['import_ids']+[imported])
    def observe(self,token,protocol,peer,method,bytes_count,digest):
        with self.lock:
            row=self.tokens.get(token)
            if self.closed or not row or time.monotonic()>row['expires'] or self.count>=self.limit:return False
            self.count+=1;metadata={'interaction_id':uuid.uuid4().hex,'correlation_id':row['id'],'protocol':protocol,'received_at':now(),'peer_address':peer,'method_or_query':method,'body_bytes':bytes_count,'body_sha256':digest,'probe_capture_id':row['bound_capture_id'],'baseline_event_id':row['baseline_event_id'],'run_id':row['run_id'],'limit':'Matching unguessable issued token observed at this receiver. Peer may be a resolver/proxy/operator; application causality, exploitation and sensitive data access require separate validation.'}
            event={'id':metadata['interaction_id'],'url':row['target'],'captured_at':metadata['received_at'],'request':{},'parameters':[],'links':[],'out_of_band':metadata}
            new_finding=protocol not in row['reported_protocols']
            if new_finding:
                event['issue']={'name':'Correlated out-of-band '+protocol+' interaction','type':'atlas-oob-'+protocol.lower(),'severity':'medium','confidence':'receiver observed matching issued correlation token','detail':'A bounded owner-controlled receiver observed an issued token associated with this resource/parameter. Source causality and vulnerability impact require validation; this is a scanner-reported interaction, not demonstrated SSRF/RCE or data disclosure.'};row['reported_protocols'].add(protocol)
            imported=self.tools.capture(self.workspace,event,'web-scanner',{**self.config,'retain_body':False});self.interactions.append(metadata);self.interactions=self.interactions[-100:]
            current=next(r for r in self.tools.store.web_runs(self.workspace) if r['id']==self.run['id']);self.tools.store.update_web_run(self.workspace,self.run['id'],requests=0,interactions=self.count,import_ids=current['import_ids']+[imported])
            if row['run_id']:
                totals=self.totals.setdefault(row['run_id'],{'interactions':0,'findings':0,'import_ids':[]});totals['interactions']+=1;totals['findings']+=int(new_finding);totals['import_ids'].append(imported)
                main=next((r for r in self.tools.store.web_runs(self.workspace) if r['id']==row['run_id']),None)
                if main:self.tools.store.update_web_run(self.workspace,row['run_id'],oob_interactions=totals['interactions'],oob_findings=totals['findings'],oob_import_ids=totals['import_ids'],findings=main.get('ordinary_findings',0)+totals['findings'])
            return True
    def summary_for(self,run_id):
        with self.lock:return copy.deepcopy(self.totals.get(run_id,{'interactions':0,'findings':0,'import_ids':[]}))
    def correlated(self,reference):
        with self.lock:return any(r['correlation_id']==reference for r in self.interactions)
    def scrub(self,event):
        with self.lock:tokens=list(self.tokens)
        if not tokens:return event
        pattern=re.compile('|'.join(tokens))
        def visit(value,key=''):
            if isinstance(value,str) and key in ('body','value'):return pattern.sub('[callback token withheld]',value)
            if isinstance(value,list):return [visit(v) for v in value]
            if isinstance(value,dict):return {k:visit(v,k) for k,v in value.items()}
            return value
        return visit(event)
    def status(self):
        with self.lock:return {'id':self.run['id'],'state':'stopped' if self.closed else 'running','callback_origin':self.origin,'dns_domain':self.domain,'dns_port':self.dns.server_address[1],'interactions':copy.deepcopy(self.interactions),'issued_tokens':len(self.tokens),'limit':'Tokens are transient; HTTP/DNS metadata and findings are saved. No automatic firewall, DNS delegation or public hosting changes.'}
    def _deadline(self):
        while not self.closed and time.monotonic()-self.started<self.seconds:time.sleep(.25)
        if not self.closed:self.close('Interaction time limit reached')
    def close(self,reason='Operator stopped interaction receiver'):
        with self.lock:
            if self.closed:return
            self.closed=True;self.tokens.clear()
        self.http.shutdown();self.http.server_close();self.dns.shutdown();self.dns.server_close();self.tools.store.update_web_run(self.workspace,self.run['id'],state='stopped',reason=reason,ended_at=now(),interactions=self.count)


class BoundedServer:
    def __init__(self,*args,**kwargs):self.slots=threading.BoundedSemaphore(8);super().__init__(*args,**kwargs)
    def process_request(self,request,address):
        if not self.slots.acquire(False):self.shutdown_request(request);return
        try:super().process_request(request,address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()
    def handle_error(self,*_):pass


class HTTPReceiver(BoundedServer,ThreadingHTTPServer):daemon_threads=True


class HTTPHandler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def receive(self):
        try:
            self.connection.settimeout(2)
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))>1:raise ValueError()
            length=int(self.headers.get('Content-Length','0'))
            if not 0<=length<=8192:raise ValueError()
            match=re.fullmatch(r'/c/([0-9a-f]{48})(?:\?[^\r\n]{0,512})?',self.path)
            if not match:raise ValueError()
            body=self.rfile.read(length)
            accepted=self.server.owner.observe(match[1],'HTTP',self.client_address[0],self.command,len(body),hashlib.sha256(body).hexdigest())
            self.send_response(204 if accepted else 404);self.send_header('Content-Length','0');self.send_header('Connection','close');self.end_headers()
        except (OSError,ValueError,ImportProblem):
            try:self.send_response(400);self.send_header('Content-Length','0');self.end_headers()
            except OSError:pass
        self.close_connection=True
    do_GET=receive;do_POST=receive;do_HEAD=receive;do_PUT=receive


class DNSReceiver(BoundedServer,socketserver.ThreadingUDPServer):daemon_threads=True;allow_reuse_address=False


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request
        try:
            if not 17<=len(data)<=512 or data[2]&0x80 or struct.unpack('!H',data[4:6])[0]!=1:return
            index=12;labels=[]
            while data[index]:
                size=data[index]
                if not 1<=size<=63 or index+size+1>=len(data) or len(labels)>10:return
                labels.append(data[index+1:index+1+size].decode('ascii').lower());index+=size+1
            index+=1
            if index+4>len(data):return
            name='.'.join(labels);owner=self.server.owner;token=labels[0]
            accepted=False
            if len(token)==48 and name==token+'.'+owner.domain:accepted=owner.observe(token,'DNS',self.client_address[0],'DNS query',len(data),hashlib.sha256(data).hexdigest())
            # Authoritative empty answer; no recursion, reflection payload or invented resolution.
            response=data[:2]+struct.pack('!HHHHH',0x8400 if accepted else 0x8403,1,0,0,0)+data[12:index+4];sock.sendto(response,self.client_address)
        except (ValueError,IndexError,UnicodeError,OSError):return
