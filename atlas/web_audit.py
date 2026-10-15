"""Bounded crawl-driven audit with explicit original checks and evidence controls."""
import copy
import hashlib
import json
import re
import time
import uuid
from collections import deque
from contextlib import nullcontext
from urllib.parse import parse_qsl,urlencode,urlsplit,urlunsplit

from .importers import ImportProblem
from .store import now
from .web_auth import AuthSession
from .web_evidence import safe_url,web_url
from .web_transport import fetch,request_headers

CHECKS=('passive','sql-error','template-expression','html-reflection','cors-origin','authorization','sql-boolean','nosql-error','ldap-error','xpath-error','command-arithmetic','file-canary','open-redirect','xml-entity','csrf-canary','cache-canary','oob-http','oob-xml')
SQL_ERROR=re.compile(r'SQL syntax.*MySQL|Unclosed quotation mark|ORA-\d{5}|SQLSTATE\[|sqlite3?\.OperationalError|PostgreSQL.*ERROR',re.I)


def validate_audit(scope,config):
    checks=config.get('checks',['passive'])
    if not isinstance(checks,list) or not checks or len(checks)>len(CHECKS) or any(c not in CHECKS for c in checks):raise ImportProblem('Choose supported original audit checks.')
    if any(c!='passive' for c in checks) and config.get('active_audit') is not True:raise ImportProblem('Enable active auditing explicitly for selected probe/authorization checks.')
    requests=config.get('audit_requests',[])
    if not isinstance(requests,list) or len(requests)>30:raise ImportProblem('At most thirty explicit audit requests are supported.')
    for row in requests:
        if not isinstance(row,dict):raise ImportProblem('Invalid audit request.')
        scope.check(row.get('url',''))
        if row.get('method','GET') not in ('GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD'):raise ImportProblem('Unsupported audit method.')
        if row.get('method','GET')!='GET' and config.get('active_audit') is not True:raise ImportProblem('Non-GET audit requests need explicit active auditing.')
        request_headers(row.get('headers',[]))
        if not isinstance(row.get('body',''),str) or len(row.get('body','').encode())>16384:raise ImportProblem('Audit request body exceeds 16 KiB.')
    if 'authorization' in checks:
        marker=config.get('protected_marker','')
        if not config.get('auth') or not isinstance(marker,str) or not 4<=len(marker)<=200:raise ImportProblem('Authorization comparison needs authentication and an explicit protected-content marker.')
    rules=config.get('custom_checks',[])
    if not isinstance(rules,list) or len(rules)>10:raise ImportProblem('At most ten declarative response checks.')
    rule_ids=set()
    for rule in rules:
        if not isinstance(rule,dict) or not re.fullmatch(r'[a-z0-9-]{1,50}',str(rule.get('id',''))) or not isinstance(rule.get('name'),str) or not 1<=len(rule['name'])<=150 or rule.get('severity','info') not in ('info','low','medium'):raise ImportProblem('Custom checks need a bounded ID, name and info/low/medium severity.')
        if rule['id'] in rule_ids:raise ImportProblem('Custom check IDs must be unique.')
        rule_ids.add(rule['id'])
        conditions=rule.get('match',{})
        if not isinstance(conditions,dict) or not conditions or set(conditions)-{'status','body_contains','header','header_equals'}:raise ImportProblem('Custom checks use literal status/body/header predicates; uploaded code and regular expressions are not executed.')
        if 'status' in conditions and (not isinstance(conditions['status'],int) or not 100<=conditions['status']<=599):raise ImportProblem('Invalid custom check status.')
        for key in ('body_contains','header','header_equals'):
            if key in conditions and (not isinstance(conditions[key],str) or not 1<=len(conditions[key])<=200):raise ImportProblem('Custom check literals must be 1–200 characters.')
        if ('header' in conditions)!=('header_equals' in conditions):raise ImportProblem('Header predicate needs a name and exact value.')
    excluded=config.get('exclude_parameters',[])
    if not isinstance(excluded,list) or len(excluded)>100 or any(not isinstance(v,str) or len(v)>200 for v in excluded):raise ImportProblem('Excluded parameter names must be a bounded list.')
    from .web_check_families import validate
    validate(scope,config)
    return checks


def insert(request,location,name,value):
    result=copy.deepcopy(request)
    if location=='query':
        parts=urlsplit(result['url']);pairs=parse_qsl(parts.query,keep_blank_values=True,max_num_fields=100)
        pairs=[(k,value if k==name else v) for k,v in pairs]
        result['url']=urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(pairs),''))
    elif location=='form':
        pairs=parse_qsl(result.get('body',''),keep_blank_values=True,max_num_fields=100);result['body']=urlencode([(k,value if k==name else v) for k,v in pairs])
    else:
        obj=json.loads(result.get('body','{}'));obj[name]=value;result['body']=json.dumps(obj)
    return result


def insertion_points(request,excluded):
    points=[('query',k) for k,_ in parse_qsl(urlsplit(request['url']).query,keep_blank_values=True,max_num_fields=100)]
    headers=request_headers(request.get('headers',[]));content=next((v for k,v in headers.items() if k.lower()=='content-type'),'')
    try:
        if 'application/x-www-form-urlencoded' in content:points.extend(('form',k) for k,_ in parse_qsl(request.get('body',''),keep_blank_values=True,max_num_fields=100))
        elif 'application/json' in content:
            obj=json.loads(request.get('body','{}'))
            if isinstance(obj,dict):points.extend(('json',k) for k,v in obj.items() if isinstance(v,(str,int,float)))
    except ValueError:pass
    return list(dict.fromkeys((loc,name) for loc,name in points if name not in excluded and not re.search(r'password|token|csrf|secret|session|api.?key',name,re.I)))[:10]


class Interrupted(Exception):
    def __init__(self,state,reason):self.state=state;self.reason=reason


def run_scan(tools,workspace,run,scope,config,stop):
    from .web_tools import passive_checks
    plan=run['plan'];started=time.monotonic();count=0;imports=[];errors=[];skipped=0;audited=0;findings=0;reported=set();auth=None;last_guard=0;refreshes=0
    state='completed';reason='Audit queue exhausted';checks=config.get('checks',['passive']);excluded=config.get('exclude_parameters',[])
    receiver=tools.receivers.get(config.get('oob_id'))
    def update_run(**values):
        # Serialize summary + write with receipts, so a fast/late callback cannot
        # be overwritten by a request or terminal-run update using stale totals.
        with receiver.lock if receiver else nullcontext():
            oob=receiver.summary_for(run['id']) if receiver else {'findings':0,'interactions':0,'import_ids':[]}
            values.update(findings=findings+oob['findings'],oob_findings=oob['findings'],oob_interactions=oob['interactions'],oob_import_ids=oob['import_ids'])
            values['authentication'] = {'mode': 'session credentials' if auth else 'unauthenticated',
                                        'session_verified': bool(auth and auth.verified),
                                        'generation': auth.generation if auth else 0}
            tools.store.update_web_run(workspace,run['id'],**values)
    if not isinstance(excluded,list) or len(excluded)>100 or any(not isinstance(v,str) or len(v)>200 for v in excluded):raise ImportProblem('Excluded parameter names must be a bounded list.')
    def budget():
        if stop.is_set():raise Interrupted('cancelled','Operator stopped the job; completed evidence retained')
        if count>=plan['max_requests'] or time.monotonic()-started>=plan['max_seconds']:raise Interrupted('partial','Request/time limit reached; remaining endpoints/checks were not audited')
    def request(url,method='GET',headers=None,body='',anonymous=False,purpose='audit'):
        nonlocal count
        budget()
        if count:stop.wait(plan['delay_ms']/1000);budget()
        tools.block_controls(scope)
        if anonymous:
            # Comparison must be genuinely credential-free, including custom secret headers.
            headers=[{'name':k,'value':v} for k,v in request_headers(headers or []).items() if k.lower() in ('accept','content-type','user-agent')]
        elif auth:headers=auth.headers(url,headers)
        event=fetch(scope,url,method,headers,body,timeout=min(5,max(.1,plan['max_seconds']-(time.monotonic()-started))))
        count+=1
        session_problem=False
        if auth and not anonymous:
            try:auth.absorb(event)
            except ImportProblem:session_problem=True;event['error']='Session cookie/token limits failed; audit stopped'
        event['authentication']={'mode':'anonymous control' if anonymous else 'session credentials' if auth and web_url(url)[0] in auth.origins else 'unauthenticated','session_verified':bool(auth and auth.verified and not anonymous),'purpose':purpose,'generation':auth.generation if auth else 0}
        imports.append(tools.capture(workspace,auth.scrub(event) if auth else event,'web-enumeration',{**config,'retain_body':False} if purpose=='login sequence' or session_problem else config))
        if event.get('error'):errors.append(event['error'])
        update_run(requests=count,import_ids=imports,errors=errors[:100],skipped=skipped,audited_endpoints=audited,ordinary_findings=findings)
        if session_problem:raise Interrupted('failed','Session cookie/token limits failed; completed metadata retained and auditing stopped')
        if auth and auth.verified and not anonymous and purpose=='audit' and event.get('response',{}).get('status') in (401,403):verify()
        return event
    def verify():
        nonlocal last_guard,refreshes
        guard=request(auth.guard,purpose='session verification')
        if not auth.valid(guard):
            auth.verified=False
            if auth.config.get('steps') and refreshes<2:
                refreshes+=1;auth.login(request)
            else:raise Interrupted('partial','Authentication was lost; scanning stopped before further audit')
        auth.verified=True;last_guard=count
    def report(event,issue,baseline=None,parameter=None,controls=None):
        nonlocal findings
        key=(web_url(event['url'])[:2],issue['type'],parameter)
        if key in reported:return
        reported.add(key);indicator=copy.deepcopy(event);indicator['id']=uuid.uuid4().hex;indicator['source_capture_id']=event['id'];indicator['issue']=issue
        indicator['test']={'baseline_event_id':baseline['id'] if baseline else event['id'],'baseline_response_sha256':(baseline or event).get('response',{}).get('body_sha256'),'parameter':parameter,'control_event_ids':[e['id'] for e in (controls or [])],'run_id':run['id'],'scope':'bounded original audit; tool-reported until operator review'}
        imports.append(tools.capture(workspace,auth.scrub(indicator) if auth else indicator,'web-scanner',config));findings+=1
    def issue(name,key,detail,severity='medium',confidence='observed controlled response difference'):
        return {'name':name,'type':key,'severity':severity,'confidence':confidence,'detail':detail+' This is scanner-reported evidence, not validated exploitability; review the linked baseline and controls.'}
    def send(row,anonymous=False,purpose='audit'):
        # Every added check uses this gate, including its neutral/repeat requests.
        if auth and not anonymous and purpose in ('audit','canary cleanup') and count-last_guard>=5:verify()
        return request(row['url'],row.get('method','GET'),row.get('headers',[]),row.get('body',''),anonymous,purpose)
    try:
        tools.store.update_web_run(workspace,run['id'],state='running')
        if config.get('auth'):
            auth=AuthSession(scope,config['auth'])
            # Distinguish a signed-in sentinel from a public/login response.
            control=request(auth.guard,anonymous=True,purpose='session anonymous control')
            if auth.valid(control):raise Interrupted('failed','Session marker is visible anonymously; choose a genuinely protected session check')
            auth.login(request);last_guard=count
        initial={'url':config.get('request_url') or config['url'],'method':config.get('method','GET') if run['kind']=='matrix' else 'GET','body':config.get('body','') if run['kind']=='matrix' else '', 'headers':config.get('headers',[])}
        queue=deque([(initial,0)])
        origin=web_url(config['url'])[0]
        queue.extend(({'url':origin+p},0) for p in config.get('paths',[]));queue.extend((row,0) for row in config.get('audit_requests',[]));seen=set()
        while queue:
            row,depth=queue.popleft();key=(row.get('method','GET'),row['url'],hashlib.sha256(row.get('body','').encode()).hexdigest())
            if key in seen:continue
            seen.add(key)
            try:scope.check(row['url'])
            except ImportProblem:skipped+=1;continue
            if auth and count-last_guard>=5:verify()
            baseline=send(row);response=baseline.get('response',{})
            if auth and (response.get('status') in (401,403) or baseline.get('redirect_url')):verify()
            if not response or response.get('truncated'):skipped+=1;continue
            audited+=1
            if 'passive' in checks:
                for result in passive_checks(baseline):report(baseline,result)
            for rule in config.get('custom_checks',[]):
                match=rule['match'];hs={h['name'].lower():h['value'] for h in response['headers']}
                if ('status' not in match or response['status']==match['status']) and ('body_contains' not in match or match['body_contains'] in response['body']) and ('header' not in match or hs.get(match['header'].lower())==match['header_equals']):report(baseline,issue(rule['name'],'atlas-custom-'+rule['id'],'Operator-defined literal response predicates matched. The rule is declarative data, not executable code; impact requires review.',rule.get('severity','info')))
            if run['kind']=='matrix':
                from .web_advanced import payload_plan
                for candidate,changes in payload_plan(row,config):
                    if auth and count-last_guard>=5:verify()
                    result=send(candidate);rp=result.get('response',{})
                    reflected=any(value and value in rp.get('body','') for _,value in changes);changed=bool(rp and rp['status']!=response['status'])
                    if reflected or changed:
                        names=','.join(key[1] for key,_ in changes)
                        report(result,issue('Multi-position payload response indicator','atlas-matrix-'+hashlib.sha256(json.dumps(changes).encode()).hexdigest()[:12],'A supplied payload was reflected or changed HTTP status from its baseline. No script execution, authentication bypass or exploit was demonstrated.','info'),baseline,names)
                continue
            if 'authorization' in checks and row.get('method','GET')=='GET' and config['protected_marker'] in response['body']:
                control=send(row,True,'anonymous authorization comparison')
                if control.get('response',{}).get('status')==response['status'] and config['protected_marker'] in control['response']['body']:
                    report(control,issue('Protected-content marker also returned anonymously','atlas-authorization-comparison','An explicitly selected protected-content marker occurred in both authenticated and credential-free responses. The marker alone does not establish object sensitivity or unauthorized access.'),baseline,controls=[control])
            if 'cors-origin' in checks:
                probe=copy.deepcopy(row);probe['headers']=[{'name':k,'value':v} for k,v in request_headers(row.get('headers',[])).items() if k.lower()!='origin']+[{'name':'Origin','value':'https://atlas-cors.invalid'}]
                result=send(probe);hs={h['name'].lower():h['value'] for h in result.get('response',{}).get('headers',[])}
                if hs.get('access-control-allow-origin')=='https://atlas-cors.invalid' and hs.get('access-control-allow-credentials','').lower()=='true':report(result,issue('Arbitrary Origin reflected with credentials declaration','atlas-cors-origin','The supplied reserved-domain Origin was reflected with Allow-Credentials. Browser readability, SameSite behavior and sensitive-data impact remain unverified.'),baseline)
            from .web_check_families import audit
            audit(row,baseline,config,send,report,issue,receiver,run['id'])
            for location,name in insertion_points(row,excluded):
                for check in checks:
                    if check not in ('sql-error','template-expression','html-reflection'):continue
                    if auth and count-last_guard>=5:verify()
                    if check=='sql-error':
                        probe=send(insert(row,location,name,"ATLAS'\""));text=probe.get('response',{}).get('body','')
                        if SQL_ERROR.search(text) and not SQL_ERROR.search(response['body']):
                            control=send(insert(row,location,name,'ATLAS_CONTROL'));repeat=send(insert(row,location,name,"ATLAS'\""))
                            if not SQL_ERROR.search(control.get('response',{}).get('body','')) and SQL_ERROR.search(repeat.get('response',{}).get('body','')):report(probe,issue('Input triggers a repeatable database error signature','atlas-sql-error-differential','A quote-bearing probe caused a database error absent from baseline/neutral control and repeated on confirmation. No query control or data access was demonstrated.'),baseline,name,[control,repeat])
                    elif check=='template-expression':
                        a=137+int(uuid.uuid4().hex[:2],16);b=211;token=uuid.uuid4().hex[:8]
                        probe=send(insert(row,location,name,token+'{{'+str(a)+'*'+str(b)+'}}'));expected=token+str(a*b)
                        if expected in probe.get('response',{}).get('body','') and expected not in response['body']:
                            control=send(insert(row,location,name,token+'ATLAS_CONTROL'));repeat=send(insert(row,location,name,token+'{{'+str(a)+'*'+str(b+1)+'}}'))
                            if expected not in control.get('response',{}).get('body','') and token+str(a*(b+1)) in repeat.get('response',{}).get('body',''):report(probe,issue('Server response evaluates two template arithmetic probes','atlas-template-expression','Two distinct bounded arithmetic expressions produced their expected products with a unique marker; baseline and literal control did not. Engine, reachable operations and impact require review.'),baseline,name,[control,repeat])
                    else:
                        token='atlas-'+uuid.uuid4().hex[:12];payload='<atlas-probe data-marker="'+token+'">';probe=send(insert(row,location,name,payload));rp=probe.get('response',{});hs={h['name'].lower():h['value'] for h in rp.get('headers',[])}
                        if 'text/html' in hs.get('content-type','') and payload in rp.get('body',''):report(probe,issue('Unescaped markup probe reflected in HTML','atlas-html-reflection','An inert custom-element probe appeared verbatim in HTML. Script execution, DOM context and cross-site impact were not tested.','low'),baseline,name)
            if config.get('audit_crawl') is True and depth<plan['max_depth']:
                for link in baseline.get('links',[]):
                    if link['kind'] in ('a','redirect','script','link'):
                        try:scope.check(link['url']);queue.append(({'url':link['url'].split('#')[0]},depth+1))
                        except ImportProblem:skipped+=1
        if auth:verify()
        if errors:state='partial';reason='Some requests failed; completed evidence retained'
    except Interrupted as exc:state=exc.state;reason=exc.reason
    except (ImportProblem,ValueError,TypeError):state='failed';reason='Authentication/audit configuration or response processing failed; completed evidence retained'
    except Exception:state='failed';reason='Audit processing failed; completed evidence retained'
    finally:
        try:
            update_run(state=state,requests=count,import_ids=imports,errors=errors[:100],skipped=skipped,audited_endpoints=audited,ordinary_findings=findings,session_refreshes=refreshes,ended_at=now(),reason=reason)
        finally:
            if auth:auth.clear()
