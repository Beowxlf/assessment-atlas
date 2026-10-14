"""Native scoped web jobs, request workbench, payload tests and explicit checks."""
import copy
import difflib
import hashlib
import json
import re
import threading
import time
import uuid
from collections import deque
from urllib.parse import parse_qsl,urlencode,urlsplit,urlunsplit

from . import __version__
from .importers import ImportProblem,clean
from .store import now
from .web_transport import Scope,fetch
from .web_evidence import safe_url


def bounded_int(config,key,default,low,high):
    value=config.get(key,default)
    if isinstance(value,bool) or not isinstance(value,int) or not low<=value<=high:raise ImportProblem(f'{key} must be {low}–{high}.')
    return value


def passive_checks(event):
    response=event.get('response')
    if not response:return []
    headers={h['name'].lower():h['value'] for h in response['headers']};html='text/html' in headers.get('content-type','').lower();issues=[]
    def add(name,key,severity,detail):issues.append({'name':name,'type':key,'severity':severity,'confidence':'observed response indicator','detail':detail+' This is a source-reported indicator, not validated exploitability.'})
    if html and 'content-security-policy' not in headers:add('HTML response has no Content-Security-Policy','atlas-csp','low','The captured HTML response had no CSP header; application/browser context requires review.')
    if event['url'].startswith('https:') and 'strict-transport-security' not in headers:add('HTTPS response has no HSTS header','atlas-hsts','low','No HSTS header was observed on this HTTPS response; existing browser policy and deployment context were not assessed.')
    if headers.get('access-control-allow-origin')=='*' and headers.get('access-control-allow-credentials','').lower()=='true':add('Wildcard CORS with credentials declaration','atlas-cors','info','This combination was observed. Modern browsers reject wildcard credentialed access; no cross-origin data disclosure is established.')
    for header in response['headers']:
        if header['name'].lower()!='set-cookie':continue
        attributes=header['value'].lower()
        if 'httponly' not in attributes:add('Cookie lacks HttpOnly attribute','atlas-cookie-httponly','low','A captured Set-Cookie header omitted HttpOnly; cookie purpose and impact require review.')
        if event['url'].startswith('https:') and not re.search(r';\s*secure(?:;|$)',attributes):add('HTTPS cookie lacks Secure attribute','atlas-cookie-secure','low','A captured Set-Cookie header omitted Secure; cookie purpose and transport context require review.')
    if html and 'x-frame-options' not in headers and 'frame-ancestors' not in headers.get('content-security-policy','').lower():add('No captured frame embedding policy','atlas-frame-policy','low','Neither X-Frame-Options nor CSP frame-ancestors was observed on this HTML response; a sensitive clickjacking action was not tested.')
    if headers.get('x-content-type-options','').lower()!='nosniff':add('Response has no nosniff directive','atlas-nosniff','info','X-Content-Type-Options: nosniff was not observed; browser/content-type context requires review.')
    if re.search(r'Traceback \(most recent call last\)|SQL syntax.*MySQL|Unclosed quotation mark|ORA-\d{5}',response['body'],re.I):add('Verbose error signature in response','atlas-error-signature','medium','A recognized error-text signature appeared in the response; its origin, sensitive content and causal mechanism require validation.')
    return issues[:10]


class WebTools:
    def __init__(self,store,port):self.store=store;self.port=port;self.lock=threading.RLock();self.jobs={};self.volatile={};self.proxies={};self.browsers={};self.sessions={};self.sockets={};self.receivers={}

    def block_controls(self,scope):
        with self.lock:scope.forbidden_ports.update(p.server.server_address[1] for p in self.proxies.values() if not p.closed)
        with self.lock:
            for r in self.receivers.values():
                if not r.closed:scope.forbidden_ports.update((r.http.server_address[1],r.dns.server_address[1]))
        scope.check(scope.start)

    def session_list(self,workspace):
        with self.lock:
            for key,row in list(self.sessions.items()):
                if row['expires']<time.monotonic():self.sessions.pop(key)['config'].clear()
            return [{'id':key,'label':row['label'],'remaining_seconds':max(0,int(row['expires']-time.monotonic()))} for key,row in self.sessions.items() if row['workspace']==workspace]

    def save_session(self,workspace,config):
        from .web_auth import AuthSession
        scope=Scope(config,self.port);auth=AuthSession(scope,config.get('auth',{}));auth.clear()
        self.session_list(workspace)
        with self.lock:
            if len(self.sessions)>=8:raise ImportProblem('At most eight transient authentication sessions; discard an unused session first.')
            key=uuid.uuid4().hex;self.sessions[key]={'workspace':workspace,'label':clean(config.get('session_label','Assessment session'))[:100],'expires':time.monotonic()+3600,'config':copy.deepcopy(config['auth'])}
        return {'id':key,'retention':'Memory only, expires after one hour or server restart. Running scans keep their own bounded session.'}

    def forget_session(self,workspace,key):
        with self.lock:
            row=self.sessions.get(key)
            if not row or row['workspace']!=workspace:raise ImportProblem('Session not found in this workspace.')
            self.sessions.pop(key)['config'].clear()
        return {'discarded':True}

    def session_config(self,workspace,config):
        config=copy.deepcopy(config)
        if config.get('session_id'):
            self.session_list(workspace)
            with self.lock:
                row=self.sessions.get(config['session_id'])
                if not row or row['workspace']!=workspace:raise ImportProblem('Session expired or belongs to another workspace.')
                config['auth']=copy.deepcopy(row['config'])
        return config
    def capture(self,workspace,event,source,config):
        event=copy.deepcopy(event)
        with self.lock:receivers=[r for r in self.receivers.values() if r.workspace==workspace and not r.closed]
        for receiver in receivers:event=receiver.scrub(event)
        for part in ('request','response'):
            if isinstance(event.get(part),dict) and len(event[part].get('body',''))>8192:
                event[part]['body']=event[part]['body'][:8192];event[part]['excerpt_truncated']=True
        data={'format':'atlas-web/1','source':source,'tool_version':'Assessment Atlas '+__version__,'capture_mode':'redacted' if config.get('retain_body') is True else 'metadata','events':[event]}
        result=self.store.import_file(workspace,json.dumps(data,ensure_ascii=False),source+'-'+event['id']+'.json',source,{'vantage':clean(config.get('vantage','Atlas local operator'))[:500],'namespace':clean(config.get('namespace','web'))[:500]},intake='native live')
        return result['import']['id']

    def start(self,workspace,kind,config):
        if kind not in ('crawl','payload','scanner','matrix'):raise ImportProblem('Unknown web run type.')
        config=self.session_config(workspace,config)
        scope=Scope(config,self.port)
        self.block_controls(scope)
        scope.check(config.get('request_url') or config['url'])
        limit=bounded_int(config,'max_requests',40,1,200);seconds=bounded_int(config,'max_seconds',60,1,300);delay=bounded_int(config,'delay_ms',500,250,10000);depth=bounded_int(config,'max_depth',2,0,4)
        paths=config.get('paths',[]);payloads=config.get('payloads',[])
        if not isinstance(paths,list) or len(paths)>50 or any(not isinstance(p,str) or len(p)>512 or not p.startswith('/') for p in paths):raise ImportProblem('Supply at most fifty explicit /paths of up to 512 characters.')
        origin=next(iter(scope.origins))
        for path in paths:scope.check(origin+path)
        if kind=='payload':
            if not isinstance(payloads,list) or not 1<=len(payloads)<=20 or any(not isinstance(p,str) or len(p)>512 for p in payloads):raise ImportProblem('Supply one to twenty bounded payloads.')
            parameter=config.get('parameter','')
            if not isinstance(parameter,str) or not parameter or len(parameter)>200:raise ImportProblem('Select one named query or form parameter.')
            if config.get('parameter_location','query') not in ('query','form'):raise ImportProblem('Payload location is query or form.')
        if config.get('auth') and kind not in ('scanner','matrix'):raise ImportProblem('Use the authenticated scanner or multi-position tests for a saved session.')
        if kind in ('scanner','matrix'):
            from .web_audit import validate_audit
            checks=validate_audit(scope,config)
            if any(c.startswith('oob-') for c in checks):
                receiver=self.receivers.get(config.get('oob_id'))
                if not receiver or receiver.workspace!=workspace or receiver.closed:raise ImportProblem('Choose an active interaction receiver from this workspace.')
            if kind=='matrix':
                from .web_advanced import payload_plan
                payload_plan({'url':config.get('request_url') or config['url'],'method':config.get('method','GET'),'body':config.get('body',''),'headers':config.get('headers',[])},config)
                if config.get('active_audit') is not True:raise ImportProblem('Enable active testing for multi-position payloads.')
            if config.get('auth'):
                from .web_auth import AuthSession
                validated_auth=AuthSession(scope,config['auth']);auth_summary=validated_auth.summary();validated_auth.clear()
        retained={k:clean(config.get(k,'')) for k in ('vantage','namespace','parameter','parameter_location')}
        plan={**scope.summary(),**retained,'url':safe_url(config['url']),'max_requests':limit,'max_seconds':seconds,'delay_ms':delay,'max_depth':depth,'path_count':len(paths),'payload_count':len(payloads),'capture_mode':'redacted' if config.get('retain_body') else 'metadata'}
        if kind in ('scanner','matrix'):plan.update(checks=checks,http_version=scope.protocol,audit_crawl=config.get('audit_crawl') is True,explicit_audit_requests=len(config.get('audit_requests',[])),authentication=auth_summary if config.get('auth') else {'mode':'unauthenticated'},oob_receiver_id=config.get('oob_id'))
        if kind=='matrix':plan.update(attack_mode=config.get('attack_mode','sniper'),positions=[{'name':p['name'],'location':p['location'],'payload_count':len(p['payloads'])} for p in config['positions']],processor=config.get('processor','none'))
        with self.lock:
            if sum(not j['stop'].is_set() and j['thread'].is_alive() for j in self.jobs.values())>=2:raise ImportProblem('At most two active web jobs are supported.')
            run=self.store.start_web_run(workspace,kind,plan);stop=threading.Event()
            thread=threading.Thread(target=self._job,args=(workspace,run,scope,copy.deepcopy(config),stop),daemon=True)
            self.jobs[run['id']]={'workspace':workspace,'stop':stop,'thread':thread};thread.start()
        return run

    def _job(self,workspace,run,scope,config,stop):
        if run['kind'] in ('scanner','matrix'):
            from .web_audit import run_scan
            return run_scan(self,workspace,run,scope,config,stop)
        state='completed';reason='Queue exhausted';count=0;imports=[];errors=[];skipped=0;started=time.monotonic();plan=run['plan'];kind=run['kind']
        selected=config.get('request_url') or config['url']
        queue=deque([(selected,0,None)]);seen=set();baseline=None
        if kind=='crawl':
            origin=next(iter(scope.origins));queue.extend((origin+p,0,None) for p in config.get('paths',[]))
        if kind=='payload':queue.extend((selected,0,p) for p in config['payloads'])
        self.store.update_web_run(workspace,run['id'],state='running')
        try:
            while queue:
                if stop.is_set():state='cancelled';reason='Operator stopped the job';break
                if count>=plan['max_requests'] or time.monotonic()-started>=plan['max_seconds']:state='partial';reason='Request/time limit reached';break
                url,level,payload=queue.popleft()
                if kind=='crawl' and url in seen:continue
                seen.add(url)
                try:scope.check(url)
                except ImportProblem:skipped+=1;continue
                method=config.get('method','GET') if kind=='payload' else 'GET';body=config.get('body','') if kind=='payload' else '';headers=config.get('headers',[])
                if payload is not None:
                    parameter=config['parameter'];location=config.get('parameter_location','query')
                    if location=='query':
                        parts=urlsplit(url);pairs=parse_qsl(parts.query,keep_blank_values=True,max_num_fields=100);pairs=[(k,payload if k==parameter else v) for k,v in pairs]
                        if not any(k==parameter for k,_ in pairs):pairs.append((parameter,payload))
                        url=urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(pairs),''))
                    else:
                        pairs=parse_qsl(body,keep_blank_values=True,max_num_fields=100);pairs=[(k,payload if k==parameter else v) for k,v in pairs]
                        if not any(k==parameter for k,_ in pairs):pairs.append((parameter,payload))
                        body=urlencode(pairs);method='POST'
                        headers=[{'name':'Content-Type','value':'application/x-www-form-urlencoded'}]+([h for h in headers if h['name'].lower()!='content-type'] if isinstance(headers,list) else [])
                self.block_controls(scope)
                event=fetch(scope,url,method,headers,body,timeout=min(5,max(.1,plan['max_seconds']-(time.monotonic()-started))))
                count+=1;imports.append(self.capture(workspace,event,'web-payload' if kind=='payload' else 'web-enumeration',config))
                if event.get('error'):errors.append(event['error'])
                if kind=='scanner':
                    for issue in passive_checks(event):
                        indicator=copy.deepcopy(event);indicator['source_capture_id']=event['id'];indicator['id']=uuid.uuid4().hex;indicator['issue']=issue;imports.append(self.capture(workspace,indicator,'web-scanner',config))
                if kind=='payload':
                    if payload is None:baseline=event
                    elif event.get('response'):
                        reflection=payload and payload in event['response']['body']
                        differential=bool(baseline and baseline.get('response') and baseline['response']['status']!=event['response']['status'])
                        event['parameters'].append({'name':config['parameter'],'location':config.get('parameter_location','query')})
                        if reflection or differential:
                            indicator=copy.deepcopy(event);indicator['source_capture_id']=event['id'];indicator['id']=uuid.uuid4().hex;indicator['issue']={'name':'Payload reflection' if reflection else 'Payload changed HTTP status','type':'atlas-payload-reflection' if reflection else 'atlas-status-difference','severity':'info','confidence':'observed differential','detail':'Selected payload reflected in captured response text; browser execution and exploitation were not established.' if reflection else 'Response status differed from the baseline. This is not proof of a vulnerability.'};indicator['test']={'baseline_event_id':baseline['id'] if baseline else None,'baseline_response_sha256':baseline.get('response',{}).get('body_sha256') if baseline else None,'parameter':config['parameter'],'payload_sha256':hashlib.sha256(payload.encode()).hexdigest(),'reflection':bool(reflection),'status_difference':differential};imports.append(self.capture(workspace,indicator,'web-scanner',config))
                if kind=='crawl' and config.get('crawl',True) and level<plan['max_depth']:
                    for link in event.get('links',[]):
                        if link['kind'] in ('a','redirect','script','link'):
                            try:scope.check(link['url']);queue.append((link['url'].split('#')[0],level+1,None))
                            except ImportProblem:skipped+=1
                self.store.update_web_run(workspace,run['id'],requests=count,import_ids=imports,errors=errors[:100],skipped=skipped)
                if queue:stop.wait(plan['delay_ms']/1000)
            if errors and state=='completed':state='partial';reason='Some requests failed; evidence retained'
        except Exception as exc:
            state='failed';reason=str(exc)[:200] if isinstance(exc,ImportProblem) else 'Job processing failed; retained completed captures';errors.append(reason)
        finally:
            self.store.update_web_run(workspace,run['id'],state=state,requests=count,import_ids=imports,errors=errors[:100],skipped=skipped,ended_at=now(),reason=reason)

    def stop(self,workspace,run_id):
        with self.lock:
            job=self.jobs.get(run_id)
            if not job or job['workspace']!=workspace:raise ImportProblem('Active job not found in this workspace.')
            job['stop'].set()
        return {'stop_requested':True,'run_id':run_id}

    def send(self,workspace,config):
        scope=Scope(config,self.port)
        self.block_controls(scope)
        event=fetch(scope,config.get('request_url') or config['url'],config.get('method','GET'),config.get('headers',[]),config.get('body',''))
        imported=self.capture(workspace,event,'web-workbench',config)
        with self.lock:
            if len(self.volatile)>=20:self.volatile.pop(next(iter(self.volatile)))
            self.volatile[event['id']]={'workspace':workspace,'event':event}
        return {'capture_id':event['id'],'import_id':imported,'event':event,'retention':'Raw editor/result is transient (up to 20 exchanges per process). Saved evidence follows selected redaction mode.'}

    def compare(self,workspace,left,right):
        with self.lock:
            pairs=[self.volatile.get(key) for key in (left,right)]
            if any(not row or row['workspace']!=workspace for row in pairs):raise ImportProblem('Choose two transient captures from this workspace; restart/reload may require resending.')
            events=[row['event'] for row in pairs]
        a,b=[json.dumps(e.get('response',{'error':e.get('error')}),sort_keys=True,indent=2) for e in events]
        return {'left':left,'right':right,'identical':a==b,'diff':'\n'.join(list(difflib.unified_diff(a.splitlines(),b.splitlines(),fromfile='First response',tofile='Second response'))[:500]),'limit':'Up to 500 difference lines; bodies bounded to 64 KiB. Transient, not a validated vulnerability.'}

    def shutdown(self):
        for job in list(self.jobs.values()):job['stop'].set()
        for browser in list(self.browsers.values()):browser.stop()
        for proxy in list(self.proxies.values()):proxy.close()
        for job in list(self.jobs.values()):job['thread'].join(timeout=6)
        for row in self.sessions.values():row['config'].clear()
        self.sessions.clear();self.volatile.clear()
        for session in list(self.sockets.values()):session.close()
        for receiver in list(self.receivers.values()):receiver.close()
