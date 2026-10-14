"""Inert codecs, token measurements, API inventory and bounded payload scheduling."""
import base64
import hashlib
import html
import itertools
import json
import math
import re
from collections import Counter
from urllib.parse import quote,unquote

from .importers import ImportProblem
from .web_audit import insert,insertion_points
from .web_evidence import web_url


def transform(text,operation):
    if not isinstance(text,str) or len(text.encode())>65536:raise ImportProblem('Utility input must be UTF-8 text of up to 64 KiB.')
    try:
        if operation=='base64-encode':return base64.b64encode(text.encode()).decode()
        if operation=='base64-decode':return base64.b64decode(text,validate=True).decode('utf-8')
        if operation=='url-encode':return quote(text,safe='')
        if operation=='url-decode':
            if re.search(r'%(?![0-9a-fA-F]{2})',text):raise ValueError()
            return unquote(text,errors='strict')
        if operation=='html-encode':return html.escape(text,quote=True)
        if operation=='html-decode':return html.unescape(text)
        if operation=='hex-encode':return text.encode().hex()
        if operation=='hex-decode':return bytes.fromhex(text).decode('utf-8')
        if operation=='json-encode':return json.dumps(text,ensure_ascii=False)
        if operation=='json-decode':
            result=json.loads(text)
            if not isinstance(result,str):raise ValueError()
            return result
        if operation=='sha256':return hashlib.sha256(text.encode()).hexdigest()
    except (ValueError,UnicodeError):raise ImportProblem('Malformed encoding or non-UTF-8 decoded text.') from None
    raise ImportProblem('Unsupported codec.')


def token_measurements(samples):
    if not isinstance(samples,list) or not 2<=len(samples)<=5000 or any(not isinstance(s,str) or not 1<=len(s)<=512 for s in samples) or sum(len(s.encode()) for s in samples)>1048576:raise ImportProblem('Supply 2–5,000 token samples, at most 512 characters each / 1 MiB total.')
    counts=Counter(samples);lengths=Counter(map(len,samples));positions=[]
    for i in range(min(map(len,samples))):
        frequency=Counter(s[i] for s in samples);n=len(samples);entropy=-sum((v/n)*math.log2(v/n) for v in frequency.values());positions.append({'position':i,'distinct_characters':len(frequency),'empirical_entropy_bits':round(entropy,4),'largest_frequency':max(frequency.values())/n})
    return {'sample_count':len(samples),'distinct_tokens':len(counts),'duplicate_samples':len(samples)-len(counts),'length_distribution':dict(lengths),'positions':positions,'limit':'Empirical sample distribution only. This is not a randomness certification, entropy lower bound, cryptographic strength or predictability verdict. Raw tokens and character values are not saved or returned.'}


def payload_plan(row,config):
    positions=config.get('positions',[]);mode=config.get('attack_mode','sniper');processor=config.get('processor','none')
    if mode not in ('sniper','battering','pitchfork','cluster') or processor not in ('none','base64-encode','url-encode','html-encode','json-encode'):raise ImportProblem('Unsupported payload mode/processor.')
    if not isinstance(positions,list) or not 1<=len(positions)<=5:raise ImportProblem('Select one to five existing query/form/JSON insertion points.')
    available=set(insertion_points(row,[]));keys=[];sets=[]
    for p in positions:
        if not isinstance(p,dict) or (p.get('location'),p.get('name')) not in available:raise ImportProblem('Payload position must exist in the selected request and must not be a credential/token parameter.')
        key=(p['location'],p['name']);values=p.get('payloads',[])
        if key in keys or not isinstance(values,list) or not 1<=len(values)<=20 or any(not isinstance(v,str) or len(v)>512 for v in values):raise ImportProblem('Positions must be unique, with 1–20 payloads of at most 512 characters.')
        keys.append(key);sets.append([v if processor=='none' else transform(v,processor) for v in values])
    if mode in ('battering','pitchfork') and any(len(s)!=len(sets[0]) for s in sets):raise ImportProblem('Battering/pitchfork modes require equally sized payload sets.')
    total=sum(map(len,sets)) if mode=='sniper' else math.prod(map(len,sets)) if mode=='cluster' else len(sets[0])
    if total>200:raise ImportProblem('Payload combinations exceed 200; reduce positions/payload sets.')
    if mode=='sniper':variants=(((key,value),) for key,values in zip(keys,sets) for value in values)
    elif mode=='battering':variants=(tuple((key,value) for key in keys) for value in sets[0])
    elif mode=='pitchfork':variants=(tuple(zip(keys,values)) for values in zip(*sets))
    else:variants=(tuple(zip(keys,values)) for values in itertools.product(*sets))
    result=[]
    for changes in variants:
        request=row
        for (location,name),value in changes:request=insert(request,location,name,value)
        result.append((request,changes))
    return result


def api_inventory(schema,scope):
    if not isinstance(schema,dict) or not re.fullmatch(r'3\.[01]\.\d+',str(schema.get('openapi',''))):raise ImportProblem('Use an OpenAPI 3.0/3.1 JSON document. External references are never fetched.')
    paths=schema.get('paths',{})
    if not isinstance(paths,dict) or len(paths)>500:raise ImportProblem('API schema exceeds 500 paths.')
    origin=web_url(scope.start)[0];requests=[];unsupported=[]
    for path,item in paths.items():
        if not isinstance(path,str) or not path.startswith('/') or len(path)>512 or not isinstance(item,dict):raise ImportProblem('Invalid API path item.')
        if '{' in path or '$ref' in item:unsupported.append({'path':path,'reason':'Needs explicit path values or local reference resolution'});continue
        scope.check(origin+path)
        for method,operation in item.items():
            if method.lower() not in ('get','post','put','patch','delete','head','options'):continue
            if not isinstance(operation,dict):raise ImportProblem('Invalid API operation.')
            if method!='get':unsupported.append({'path':path,'method':method.upper(),'reason':'Review and supply explicit body/parameters before active audit'});continue
            path_parameters=item.get('parameters',[]);operation_parameters=operation.get('parameters',[])
            if not isinstance(path_parameters,list) or not isinstance(operation_parameters,list) or len(path_parameters)+len(operation_parameters)>100:raise ImportProblem('API parameters must be bounded arrays.')
            parameters=path_parameters+operation_parameters
            if parameters:unsupported.append({'path':path,'method':'GET','reason':'Review and supply explicit parameter values'});continue
            requests.append({'url':origin+path,'method':'GET'})
    if len(requests)>30:raise ImportProblem('API inventory exceeds thirty directly auditable requests; narrow the schema.')
    return {'audit_requests':requests,'unsupported':unsupported,'limit':'Inert inventory, no network. Schema servers/references/examples/security declarations do not authorize targets, supply credentials or start scans.'}
