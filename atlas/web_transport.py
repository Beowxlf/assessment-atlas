"""Deliberate scoped HTTP/1.1 transport; DNS addresses pinned per tool session."""
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
import uuid
from html.parser import HTMLParser
from urllib.parse import urljoin, unquote, urlsplit, parse_qsl

from .importers import ImportProblem
from .web_evidence import web_url
from .store import now

MAX_BODY=65536
METHODS=('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')
FORBIDDEN_HEADERS={'host','connection','proxy-connection','proxy-authorization','content-length','transfer-encoding','upgrade','expect','accept-encoding','trailer'}


def path_key(path):
    if not isinstance(path,str) or not path.startswith('/') or len(path)>2048:raise ImportProblem('Scope paths start with / and are at most 2,048 characters.')
    decoded=path
    for _ in range(4):
        next_path=unquote(decoded)
        if next_path==decoded:break
        decoded=next_path
    if '%' in decoded or '\\' in decoded or any(ord(c)<32 for c in decoded) or any(p in ('.','..') for p in decoded.split('/')) or '//' in decoded:
        raise ImportProblem('Ambiguous, encoded traversal or backslash paths are not supported.')
    return decoded


def path_contains(prefix,path):
    prefix=path_key(prefix).rstrip('/') or '/';path=path_key(path)
    return prefix=='/' or path==prefix or path.startswith(prefix+'/')


class Scope:
    def __init__(self,config,atlas_port=None,resolve=True):
        if config.get('authorized') is not True:raise ImportProblem('Confirm authority for the exact target and scope before starting a live tool.')
        origin,path,_,_,_=web_url(config.get('url',''))
        self.start=config['url'];self.origins={origin:path_key(config.get('path_prefix','/') or '/')}
        extras=config.get('extra_origins',[])
        if not isinstance(extras,list) or len(extras)>4:raise ImportProblem('At most four explicit additional origin URLs are supported.')
        for url in extras:
            other,p,query,_,_=web_url(url)
            if query:raise ImportProblem('Additional origin scopes cannot include query values.')
            self.origins[other]=path_key(p)
        excluded=config.get('exclude_paths',[])
        if not isinstance(excluded,list) or len(excluded)>30:raise ImportProblem('At most thirty excluded path prefixes are supported.')
        self.excluded=[path_key(p) for p in excluded]
        self.atlas_port=atlas_port;self.pins={};self.forbidden_ports={atlas_port}
        self.check(self.start)
        if resolve:
            for allowed in self.origins:
                _,_,_,host,port=web_url(allowed)
                try:addresses=sorted({a[4][0] for a in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)},key=lambda a:(':' in a,a))
                except OSError:raise ImportProblem('Scope hostname resolution failed.') from None
                if not addresses or len(addresses)>16:raise ImportProblem('Scope resolution returned no usable bounded address set.')
                for address in addresses:
                    ip=ipaddress.ip_address(address)
                    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or (ip.is_loopback and port==atlas_port):raise ImportProblem('Metadata/link-local/multicast/unspecified and Atlas control targets are excluded.')
                self.pins[allowed]=addresses
        ca=config.get('ca_pem','')
        if not isinstance(ca,str) or len(ca)>32768 or ('PRIVATE KEY' in ca):raise ImportProblem('Only a bounded public CA certificate is accepted.')
        try:self.tls=ssl.create_default_context(cadata=ca or None)
        except (ssl.SSLError,ValueError):raise ImportProblem('Public CA certificate could not be loaded.') from None
        self.tls.minimum_version=ssl.TLSVersion.TLSv1_2
        self.ca_sha256=hashlib.sha256(ca.encode()).hexdigest() if ca else None

    def check(self,url):
        origin,path,_,_,_=web_url(url)
        if origin not in self.origins or not path_contains(self.origins[origin],path) or any(path_contains(p,path) for p in self.excluded):raise ImportProblem('URL is outside the explicit origin/path scope or is excluded.')
        if any(ipaddress.ip_address(a).is_loopback for a in self.pins.get(origin,[])) and web_url(url)[4] in self.forbidden_ports:raise ImportProblem('Atlas and interception control listeners cannot be targets.')
        return origin

    def summary(self):
        return {'origins':self.origins,'excluded_paths':self.excluded,'resolved_addresses':self.pins,'upstream_tls':'hostname and CA validated','custom_ca_sha256':self.ca_sha256}


def request_headers(value):
    if isinstance(value,str):
        result=[]
        for line in value.splitlines():
            if not line.strip():continue
            if ':' not in line:raise ImportProblem('Headers use one Name: value per line.')
            name,content=line.split(':',1);result.append({'name':name.strip(),'value':content.strip()})
        value=result
    if not isinstance(value,list) or len(value)>80:raise ImportProblem('At most eighty request headers are supported.')
    result={}
    for row in value:
        if not isinstance(row,dict):raise ImportProblem('Invalid request header.')
        name=row.get('name','');content=row.get('value','')
        if not isinstance(name,str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or not isinstance(content,str) or len(content)>4096 or '\r' in content or '\n' in content or '\x00' in content:raise ImportProblem('Malformed or overlong request header.')
        if name.lower() in FORBIDDEN_HEADERS:continue
        if name.lower() in {k.lower() for k in result}:raise ImportProblem('Duplicate request headers are not supported.')
        result[name]=content
    result['Accept-Encoding']='identity';result['Connection']='close'
    if not any(k.lower()=='user-agent' for k in result):result['User-Agent']='AssessmentAtlas/0.2.0 scoped web tools'
    return result


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self,host,port,address,tls=None,timeout=5):
        super().__init__(host,port,timeout=timeout);self.address=address;self.tls=tls
    def connect(self):
        self.sock=socket.create_connection((self.address,self.port),self.timeout)
        if self.tls:self.sock=self.tls.wrap_socket(self.sock,server_hostname=self.host)


class PageParser(HTMLParser):
    def __init__(self,url):super().__init__();self.url=url;self.links=[];self.parameters=[]
    def handle_starttag(self,tag,attrs):
        data=dict(attrs)
        if tag in ('a','link','script','img','iframe','form'):
            target=data.get('href') or data.get('src') or (data.get('action') if tag=='form' else None)
            if target and not target.startswith(('javascript:','data:','mailto:')) and len(self.links)<100:
                resolved=urljoin(self.url,target)
                try:web_url(resolved)
                except ImportProblem:return
                self.links.append({'url':resolved,'kind':tag})
        if tag in ('input','select','textarea') and data.get('name') and len(self.parameters)<100:self.parameters.append({'name':data['name'][:200],'location':'form'})


def fetch(scope,url,method='GET',headers=None,body='',timeout=5,wire=False):
    origin=scope.check(url);_,path,query,host,port=web_url(url)
    if method not in METHODS:raise ImportProblem('Unsupported HTTP method.')
    if not isinstance(body,str) or len(body.encode('utf-8'))>16384:raise ImportProblem('Request body exceeds 16 KiB.')
    outbound=request_headers(headers or [])
    started=time.monotonic();event={'id':uuid.uuid4().hex,'url':url,'captured_at':now(),'request':{'method':method,'url':url,'headers':[{'name':k,'value':v} for k,v in outbound.items()],'body':body,'bytes':len(body.encode()),'body_sha256':hashlib.sha256(body.encode()).hexdigest()},'parameters':[],'links':[]}
    conn=PinnedConnection(host,port,scope.pins[origin][0],scope.tls if origin.startswith('https:') else None,timeout)
    try:
        conn.request(method,path+('?' + query if query else ''),body.encode('utf-8') if body else None,outbound)
        event['upstream_tls']=conn.sock.version() if isinstance(conn.sock,ssl.SSLSocket) else None
        if isinstance(conn.sock,ssl.SSLSocket):event['peer_certificate_sha256']=hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        response=conn.getresponse();body_limit=2*1024*1024 if wire else MAX_BODY;raw=response.read(body_limit+1);truncated=len(raw)>body_limit;raw=raw[:body_limit]
        text=raw.decode('utf-8',errors='replace')
        event['response']={'status':response.status,'headers':[{'name':k,'value':v} for k,v in response.getheaders()[:100]],'body':text,'bytes':len(raw),'body_sha256':hashlib.sha256(raw).hexdigest(),'truncated':truncated,'digest_scope':'captured bytes only' if truncated else 'complete received body'}
        event['elapsed_ms']=round((time.monotonic()-started)*1000,2)
        event['connected_address']=scope.pins[origin][0]
        if 'text/html' in response.getheader('Content-Type','').lower():
            parser=PageParser(url)
            try:parser.feed(text)
            except ValueError:pass
            event['links']=parser.links;event['parameters']=parser.parameters
        location=response.getheader('Location')
        if location and response.status in (301,302,303,307,308):
            redirected=urljoin(url,location)
            event['links'].append({'url':redirected,'kind':'redirect'})
            try:scope.check(redirected);event['redirect_in_scope']=True
            except ImportProblem:event['redirect_in_scope']=False
            event['redirect_url']=redirected
        return (event,raw) if wire else event
    except (OSError,http.client.HTTPException) as exc:
        # Never leak header values, certificate paths or exception-injected content.
        event['error']='TLS validation failed' if isinstance(exc,ssl.SSLError) else 'Connection/HTTP read failed or timed out'
        event['elapsed_ms']=round((time.monotonic()-started)*1000,2)
        return (event,b'') if wire else event
    finally:conn.close()
