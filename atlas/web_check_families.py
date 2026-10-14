"""Original bounded audit families; causal controls and explicit canaries."""
import copy
import hashlib
import html
import json
import re
import uuid
from urllib.parse import quote,urlsplit

from .importers import ImportProblem
from .web_audit import insert,insertion_points
from .web_transport import request_headers

FAMILIES=('sql-boolean','nosql-error','ldap-error','xpath-error','command-arithmetic','file-canary','open-redirect','xml-entity','csrf-canary','cache-canary','oob-http','oob-xml')


def validate(scope,config):
    for check in config.get('checks',[]):
        if check=='file-canary':
            if not isinstance(config.get('canary_path'),str) or not 1<=len(config['canary_path'])<=512 or not isinstance(config.get('canary_marker'),str) or not 8<=len(config['canary_marker'])<=200:raise ImportProblem('File tests require an explicitly owned canary path and a unique 8–200 character content marker.')
        if check in ('csrf-canary','cache-canary'):
            scope.check(config.get('canary_url',''))
        if check=='csrf-canary':
            if not isinstance(config.get('canary_marker'),str) or not 8<=len(config['canary_marker'])<=200:raise ImportProblem('Stateful checks need an explicit canary URL and a unique marker.')
        if check.startswith('oob-') and not config.get('oob_id'):raise ImportProblem('Select an active owner-controlled interaction receiver for OOB checks.')


def body(event):return event.get('response',{}).get('body','')
def digest(event):return event.get('response',{}).get('body_sha256')


def audit(row,baseline,config,send,report,issue,receiver=None,run_id=None):
    checks=config.get('checks',[]);original=body(baseline)
    if 'cache-canary' in checks and row['url']==config['canary_url']:
        marker='ATLAS_CACHE_'+uuid.uuid4().hex;probe=copy.deepcopy(row);parts=urlsplit(row['url']);probe['url']=row['url']+('&' if parts.query else '?')+'atlas_cache_probe='+uuid.uuid4().hex
        probe['headers']=[{'name':k,'value':v} for k,v in request_headers(row.get('headers',[])).items() if k.lower() not in ('x-forwarded-host','cache-control')]+[{'name':'X-Forwarded-Host','value':marker+'.invalid'}]
        control=copy.deepcopy(probe);control['headers']=row.get('headers',[])
        try:
            first=send(probe);second=send(control)
            if marker in body(first) and marker in body(second):report(second,issue('Canary response retained a supplied host marker in cache','atlas-cache-canary','A unique per-test canary URL returned a supplied host marker in both probe and header-free follow-up. Shared cache keys, poisoning impact and complete invalidation remain unverified.'),baseline,controls=[first,second])
        finally:
            cleanup=copy.deepcopy(control);cleanup['headers']=[{'name':'Cache-Control','value':'no-cache, max-age=0'}];send(cleanup,purpose='canary cleanup')
    if 'csrf-canary' in checks and row['url']==config['canary_url'] and row.get('method')=='POST':
        probe=copy.deepcopy(row);headers=request_headers(row.get('headers',[]));probe['headers']=[{'name':k,'value':v} for k,v in headers.items() if not re.search(r'csrf|xsrf|origin|referer',k,re.I)]+[{'name':'Origin','value':'https://atlas-csrf.invalid'}]
        ct=next((v for k,v in headers.items() if k.lower()=='content-type'),'')
        if 'json' in ct:
            obj=json.loads(row.get('body','{}'));probe['body']=json.dumps({k:v for k,v in obj.items() if not re.search(r'csrf|xsrf',k,re.I)})
        else:
            from urllib.parse import parse_qsl,urlencode
            probe['body']=urlencode([(k,v) for k,v in parse_qsl(row.get('body',''),keep_blank_values=True) if not re.search(r'csrf|xsrf',k,re.I)])
        result=send(probe)
        if config['canary_marker'] in body(result) and result.get('response',{}).get('status',500)<300:report(result,issue('Canary request accepted without selected CSRF tokens','atlas-csrf-canary','The explicit stateful canary request succeeded with a foreign Origin and selected token fields removed. SameSite and browser feasibility were not established; review the linked request and canary state.'),baseline)
    if any(c in checks for c in ('xml-entity','oob-xml')) and 'xml' in next((v for k,v in request_headers(row.get('headers',[])).items() if k.lower()=='content-type'),''):
        if 'xml-entity' in checks:
            token='ATLAS_XML_'+uuid.uuid4().hex;probe=copy.deepcopy(row);probe['body']='<!DOCTYPE atlas [<!ENTITY probe "'+token+'">]><atlas>&probe;</atlas>';first=send(probe)
            if token in body(first) and probe['body'] not in body(first) and '<!ENTITY' not in body(first):
                second=copy.deepcopy(probe);token2='ATLAS_XML_'+uuid.uuid4().hex;second['body']=probe['body'].replace(token,token2);confirm=send(second)
                if token2 in body(confirm) and '<!ENTITY' not in body(confirm):report(first,issue('Canary XML entity values expanded in response','atlas-xml-entity','Two bounded internal entities produced their unique values. This does not establish external-entity access, file disclosure or denial of service.'),baseline,controls=[confirm])
        if 'oob-xml' in checks and receiver:
            token=receiver.allocate(row['url'],'XML external entity',baseline['id'],run_id);probe=copy.deepcopy(row);probe['body']='<!DOCTYPE atlas [<!ENTITY probe SYSTEM "'+token['callback_url']+'">]><atlas>&probe;</atlas>';event=send(probe);receiver.bind_capture(token['id'],event)
    for location,name in insertion_points(row,config.get('exclude_parameters',[])):
        for check in checks:
            if check not in FAMILIES or check in ('xml-entity','oob-xml','cache-canary','csrf-canary'):continue
            if check=='sql-boolean':
                a=send(insert(row,location,name,"' OR 1=1 -- "));b=send(insert(row,location,name,"' OR 1=2 -- "))
                if digest(a)==digest(baseline) and digest(b)!=digest(a) and 'OR 1=' not in body(a)+body(b) and a.get('response') and b.get('response'):
                    c=send(insert(row,location,name,"' OR 2=2 -- "));d=send(insert(row,location,name,"' OR 2=3 -- "))
                    if digest(c)==digest(a) and digest(d)==digest(b):report(a,issue('Repeatable true/false SQL-shaped response differential','atlas-sql-boolean','Two true-shaped requests matched baseline while two false-shaped requests matched a different response, without literal probe reflection. SQL execution/query control and sensitive-data impact remain unverified.'),baseline,name,[b,c,d])
            elif check in ('nosql-error','ldap-error','xpath-error'):
                patterns={'nosql-error':r'Mongo(?:Error|ServerError)|BSON.*(?:invalid|error)|unknown operator.*\$','ldap-error':r'LDAP.*(?:error|exception)|invalid (?:DN|filter)|Bad search filter','xpath-error':r'XPath(?:SyntaxError|Exception)|Invalid XPath|XPath.*(?:error|syntax)'}
                values={'nosql-error':'{"$atlas_invalid":1}','ldap-error':'*)(|(atlasProbe=1))','xpath-error':"'[]ATLAS"}
                probe=send(insert(row,location,name,values[check]));regex=re.compile(patterns[check],re.I)
                if regex.search(body(probe)) and not regex.search(original):
                    control=send(insert(row,location,name,'ATLAS_NEUTRAL'));repeat=send(insert(row,location,name,values[check]))
                    if not regex.search(body(control)) and regex.search(body(repeat)):report(probe,issue('Repeatable '+check+' response signature','atlas-'+check,'The selected probe introduced a repeatable error signature absent from baseline and neutral control. Backend mechanism and exploitability require separate validation.'),baseline,name,[control,repeat])
            elif check=='command-arithmetic':
                prefix='ATLAS_CMD_'+uuid.uuid4().hex[:10];a,b=137,193;value=";printf '"+prefix+"%s' $(("+str(a)+'*'+str(b)+"));";probe=send(insert(row,location,name,value))
                if prefix+str(a*b) in body(probe) and prefix+str(a*b) not in original and value not in body(probe):
                    value2=value.replace('*193','*197');confirm=send(insert(row,location,name,value2));control=send(insert(row,location,name,'ATLAS_NEUTRAL'))
                    if prefix+str(a*197) in body(confirm) and prefix not in body(control):report(probe,issue('Two shell-shaped arithmetic probes produced expected products','atlas-command-arithmetic','Two bounded printf/arithmetic inputs yielded their expected unique-marker products while a neutral control did not. Shell identity, privileges and arbitrary execution impact require validation; no files or external callbacks were requested.'),baseline,name,[confirm,control])
            elif check=='file-canary':
                probe=send(insert(row,location,name,config['canary_path']));control=send(insert(row,location,name,'atlas-missing-'+uuid.uuid4().hex))
                if config['canary_marker'] in body(probe) and config['canary_marker'] not in original+body(control):
                    confirm=send(insert(row,location,name,config['canary_path']))
                    if config['canary_marker'] in body(confirm):report(probe,issue('Explicitly selected file canary returned by input','atlas-file-canary','A selected owned-file canary marker appeared on probe/repeat but not baseline/neutral control. Arbitrary file access or sensitive-file disclosure was not tested.'),baseline,name,[control,confirm])
            elif check=='open-redirect':
                destination='https://atlas-redirect.invalid/'+uuid.uuid4().hex;probe=send(insert(row,location,name,destination));response=probe.get('response',{});location_header=next((h['value'] for h in response.get('headers',[]) if h['name'].lower()=='location'),'')
                if response.get('status') in (301,302,303,307,308) and location_header==destination:report(probe,issue('Input selected a reserved external redirect URL','atlas-open-redirect','A reserved-domain destination was returned verbatim in Location. The redirect was not followed; phishing/token impact remains unverified.'),baseline,name)
            elif check=='oob-http' and receiver:
                token=receiver.allocate(row['url'],name,baseline['id'],run_id);probe=send(insert(row,location,name,token['callback_url']));receiver.bind_capture(token['id'],probe)
