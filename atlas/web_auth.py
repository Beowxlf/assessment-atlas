"""Transient, origin-bound sessions. Credentials never enter the assessment model."""
import copy
import http.cookiejar
import json
import re
import time
from email.message import Message
from html.parser import HTMLParser
from urllib.request import Request
from urllib.parse import parse_qsl,urlencode

from .importers import ImportProblem
from .web_evidence import safe_url, web_url
from .web_transport import request_headers


class HiddenFields(HTMLParser):
    def __init__(self):super().__init__();self.values={}
    def handle_starttag(self,tag,attrs):
        row=dict(attrs)
        if tag=='input' and row.get('name') and row.get('type','').lower()=='hidden':self.values[row['name']]=row.get('value','')


class AuthSession:
    def __init__(self,scope,config):
        if not isinstance(config,dict):raise ImportProblem('Authentication configuration must be an object.')
        self.scope=scope;self.config=copy.deepcopy(config);self.jars={};self.secrets=set();self.variables={};self.verified=False;self.generation=0
        origins=config.get('origins',[web_url(scope.start)[0]])
        if not isinstance(origins,list) or not 1<=len(origins)<=5:raise ImportProblem('Authentication needs one to five exact scoped origins.')
        self.origins=set()
        for value in origins:
            origin,path,query,_,_=web_url(value)
            if origin not in scope.origins or path!='/' or query:raise ImportProblem('Authentication origins must be exact origins already in target scope.')
            self.origins.add(origin)
        self.guard=config.get('check_url','');scope.check(self.guard)
        if web_url(self.guard)[0] not in self.origins:raise ImportProblem('Session check must be on an authenticated origin.')
        self.marker=config.get('success_text','');self.expected=config.get('success_status',200)
        if not isinstance(self.marker,str) or not 1<=len(self.marker)<=200 or not isinstance(self.expected,int) or not 200<=self.expected<300:raise ImportProblem('A session check requires a 2xx status and a unique signed-in response marker (1–200 characters).')
        self.secrets.add(self.marker)
        steps=config.get('steps',[])
        if not isinstance(steps,list) or len(steps)>10:raise ImportProblem('Login sequences support up to ten explicit scoped requests.')
        for step in steps:
            if not isinstance(step,dict):raise ImportProblem('Invalid login step.')
            scope.check(step.get('url',''))
            if web_url(step['url'])[0] not in self.origins:raise ImportProblem('Login steps must be on authenticated origins.')
            if step.get('method','GET') not in ('GET','POST'):raise ImportProblem('Login sequences support GET and POST.')
            request_headers(step.get('headers',[]))
            if not isinstance(step.get('body',''),str) or len(step.get('body','').encode())>16384:raise ImportProblem('Login step body exceeds 16 KiB.')
            extract=step.get('extract',{})
            if not isinstance(extract,dict) or len(extract)>10:raise ImportProblem('At most ten token extractions per step.')
            for key,spec in extract.items():
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}',key) or not isinstance(spec,dict) or spec.get('from') not in ('json','hidden','header') or not isinstance(spec.get('name'),str) or len(spec['name'])>200:raise ImportProblem('Token extraction uses a named JSON path, hidden field or response header.')
        request_headers(config.get('headers',[]))
        self.remember(config.get('headers',[]));self.remember(steps)
        for name,value in request_headers(config.get('headers',[])).items():
            if re.search(r'authorization|cookie|token|api.?key|csrf',name,re.I):
                self.remember(value)
                if name.lower()=='cookie':
                    for part in value.split(';'):
                        if '=' in part:self.remember(part.split('=',1)[1].strip())
                elif name.lower()=='authorization':
                    for word in value.split():self.remember(word)
        cookies=config.get('cookies',[])
        if not isinstance(cookies,list) or len(cookies)>100:raise ImportProblem('Session cookie snapshot exceeds 100 cookies.')
        for row in cookies:self.seed_cookie(row)
        self.check_secret_limits()

    def check_secret_limits(self):
        if len(self.secrets)>512 or sum(len(value.encode()) for value in self.secrets)>1048576:raise ImportProblem('Transient session values exceeded bounded retention limits; scanning stopped.')

    def remember(self,value):
        if isinstance(value,str):
            if value:self.secrets.add(value)
        elif isinstance(value,list):
            for row in value:self.remember(row)
        elif isinstance(value,dict):
            for key,item in value.items():
                if key in ('body','value'):
                    self.remember(item)
                    if isinstance(item,str):
                        try:
                            obj=json.loads(item)
                            if isinstance(obj,dict):
                                for entry in obj.values():
                                    if isinstance(entry,str):self.remember(entry)
                        except ValueError:
                            for _,entry in parse_qsl(item,keep_blank_values=True,max_num_fields=100):self.remember(entry)
                        if key=='value':
                            for word in item.split():self.remember(word)

    def jar(self,origin):
        if origin not in self.jars:self.jars[origin]=http.cookiejar.CookieJar(http.cookiejar.DefaultCookiePolicy(strict_ns_domain=http.cookiejar.DefaultCookiePolicy.DomainStrict))
        return self.jars[origin]

    def seed_cookie(self,row):
        if not isinstance(row,dict):raise ImportProblem('Invalid browser cookie.')
        origin=row.get('origin');name=row.get('name');value=row.get('value');path=row.get('path','/');expires=row.get('expires',-1)
        if origin not in self.origins or not isinstance(name,str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or not isinstance(value,str) or len(value)>4096 or re.search(r'[\x00-\x20\x7f;,]',value):raise ImportProblem('Invalid origin-bound session cookie.')
        if not isinstance(path,str) or not path.startswith('/') or len(path)>2048 or not isinstance(expires,(int,float)):raise ImportProblem('Invalid cookie path/expiry.')
        host=web_url(origin)[3];expiry=int(expires) if expires>0 else None
        cookie=http.cookiejar.Cookie(0,name,value,None,False,host,False,False,path,True,row.get('secure') is True,expiry,expiry is None,None,None,{},False)
        self.jar(origin).set_cookie(cookie);self.secrets.add(value)

    def substitute(self,value):
        def replace(match):
            key=match.group(1)
            if key not in self.variables:raise ImportProblem('A login token placeholder has no extracted value.')
            return self.variables[key]
        return re.sub(r'\{\{([A-Za-z][A-Za-z0-9_]*)\}\}',replace,value)

    def headers(self,url,base=None):
        origin=self.scope.check(url);out=request_headers(base or [])
        if origin not in self.origins:
            # Ambient editor credentials cannot escape onto auxiliary crawl origins.
            return [{'name':k,'value':v} for k,v in out.items() if not re.search(r'authorization|cookie|token|api.?key|csrf',k,re.I)]
        for key,value in request_headers(self.config.get('headers',[])).items():
            if key.lower() not in ('connection','accept-encoding','user-agent'):
                if not self.verified and any(name not in self.variables for name in re.findall(r'\{\{([A-Za-z][A-Za-z0-9_]*)\}\}',value)):continue
                for old in list(out):
                    if old.lower()==key.lower():del out[old]
                out[key]=self.substitute(value)
        request=Request(url);self.jar(origin).add_cookie_header(request)
        cookie=request.get_header('Cookie')
        if cookie:
            for old in list(out):
                if old.lower()=='cookie':del out[old]
            out['Cookie']=cookie
        return [{'name':k,'value':v} for k,v in out.items()]

    def absorb(self,event):
        origin=web_url(event['url'])[0]
        if origin not in self.origins or not event.get('response'):return
        message=Message()
        for h in event['response']['headers']:message.add_header(h['name'],h['value'])
        response=type('CookieResponse',(),{'info':lambda _:message})()
        self.jar(origin).extract_cookies(response,Request(event['url']))
        jar=self.jar(origin);jar.clear_expired_cookies()
        for cookie in jar:
            if len(cookie.value.encode())>4096:raise ImportProblem('Target cookie exceeds 4 KiB; scanning stopped.')
            self.secrets.add(cookie.value)
        if len(list(jar))>100:raise ImportProblem('Target session exceeded one hundred cookies; scanning stopped.')
        self.check_secret_limits()

    def valid(self,event):
        response=event.get('response',{})
        return response.get('status')==self.expected and not response.get('truncated') and self.marker in response.get('body','')

    def login(self,request):
        for step in self.config.get('steps',[]):
            headers=[{'name':k,'value':self.substitute(v)} for k,v in request_headers(step.get('headers',[])).items()]
            body=step.get('body','');content_type=next((h['value'] for h in headers if h['name'].lower()=='content-type'),'')
            if 'application/json' in content_type and body:
                try:
                    obj=json.loads(body)
                    if not isinstance(obj,dict):raise ValueError()
                    body=json.dumps({k:self.substitute(v) if isinstance(v,str) else v for k,v in obj.items()})
                except ValueError:raise ImportProblem('Login JSON body must be an object.') from None
            elif 'application/x-www-form-urlencoded' in content_type:body=urlencode([(k,self.substitute(v)) for k,v in parse_qsl(body,keep_blank_values=True,max_num_fields=100)])
            else:body=self.substitute(body)
            event=request(step['url'],step.get('method','GET'),headers,body,False,purpose='login sequence')
            response=event.get('response',{})
            if event.get('error') or response.get('truncated') or response.get('status',500)>=400:raise ImportProblem('Login sequence failed; no authenticated audit was started.')
            for key,spec in step.get('extract',{}).items():
                try:
                    if spec['from']=='json':
                        value=json.loads(response['body'])
                        for component in spec['name'].split('.'):value=value[component]
                    elif spec['from']=='hidden':
                        parser=HiddenFields();parser.feed(response['body']);value=parser.values[spec['name']]
                    else:value=next(h['value'] for h in response['headers'] if h['name'].lower()==spec['name'].lower())
                except (ValueError,KeyError,TypeError,StopIteration):raise ImportProblem('Login token extraction failed.') from None
                if not isinstance(value,str) or not value or len(value)>4096 or '\r' in value or '\n' in value:raise ImportProblem('Login token is missing or malformed.')
                self.variables[key]=value;self.secrets.add(value)
                self.check_secret_limits()
        event=request(self.guard,'GET',[], '',False)
        if not self.valid(event):raise ImportProblem('Session check failed; authenticated scanning stopped.')
        self.verified=True;self.generation+=1
        return event

    def scrub(self,event):
        pattern=re.compile('|'.join(re.escape(s) for s in sorted(self.secrets,key=len,reverse=True) if s)) if self.secrets else None
        def scrub(value,key=''):
            if key.endswith('sha256') or key in ('id','source_capture_id','baseline_event_id','control_event_ids','run_id','captured_at','method','status','direction','opcode','encoding','mode','purpose','http_version','upstream_tls','generation','confidence','severity','type','name'):return value
            if isinstance(value,str):
                if key in ('url','redirect_url'):
                    try:
                        origin,path,query,_,_=web_url(value)
                        return origin+(pattern.sub('-',path) if pattern else path)+('?' + query if query else '')
                    except ImportProblem:return '[unmapped URL]'
                return pattern.sub('[session value withheld]',value) if pattern else value
            if isinstance(value,list):return [scrub(v) for v in value]
            if isinstance(value,dict):return {k:scrub(v,k) for k,v in value.items()}
            return value
        return scrub(copy.deepcopy(event))

    def summary(self):return {'mode':'transient origin-bound session','origins':sorted(self.origins),'check_url':safe_url(self.guard),'login_steps':len(self.config.get('steps',[])),'credential_retention':'memory only; discarded when the run ends'}
    def clear(self):
        self.config.clear();self.variables.clear();self.secrets.clear()
        for jar in self.jars.values():jar.clear()
        self.jars.clear()
