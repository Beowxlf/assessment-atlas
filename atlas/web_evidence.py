"""Inert web-evidence normalization. This module never contacts a URL."""
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, unquote

from .importers import Bundle, ImportProblem, clean, items, parse_json, timestamp

SENSITIVE = re.compile(r'authorization|cookie|password|passwd|secret|token|api.?key|csrf|session',re.I)
MAX_TEXT = 8192


def web_url(value):
    if not isinstance(value,str) or len(value)>4096 or any(ord(c)<32 for c in value):
        raise ImportProblem('Expected a bounded HTTP(S) URL.')
    try:
        p=urlsplit(value)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password:
            raise ValueError()
        host=p.hostname.encode('idna').decode('ascii').lower()
        port=p.port or (443 if p.scheme=='https' else 80)
    except (ValueError,UnicodeError):
        raise ImportProblem('URL must have an HTTP(S) origin and no embedded credentials.') from None
    if not 1<=port<=65535:raise ImportProblem('Invalid URL port.')
    authority=('['+host+']' if ':' in host else host)+(':'+str(port) if port!=(443 if p.scheme=='https' else 80) else '')
    path=p.path or '/'
    if '\\' in path:raise ImportProblem('Backslashes are not supported in web paths.')
    origin=p.scheme+'://'+authority
    return origin,path,p.query,host,port


def safe_url(value):
    origin,path,query,_,_=web_url(value)
    pairs=parse_qsl(query,keep_blank_values=True,max_num_fields=100)
    return origin+clean(path)+('?' + urlencode([(clean(k),'[withheld]') for k,_ in pairs]) if pairs else '')


def safe_headers(headers,mode='redacted'):
    if not isinstance(headers,list) or len(headers)>100:raise ImportProblem('Headers must be a bounded array.')
    result=[]
    for h in headers:
        if not isinstance(h,dict) or not isinstance(h.get('name'),str):raise ImportProblem('Invalid header.')
        name=clean(h['name'])[:120]
        value=clean(h.get('value',''))[:1000]
        if SENSITIVE.search(name):value='[redacted]'
        elif name.lower() in ('location','content-location','referer'):
            try:
                parsed=urlsplit(value)
                if parsed.scheme:value=safe_url(value)
                else:value=parsed.path+('?' + urlencode([(k,'[withheld]') for k,_ in parse_qsl(parsed.query,keep_blank_values=True,max_num_fields=100)]) if parsed.query else '')
            except (ImportProblem,ValueError):value='[unmapped URL header]'
        elif mode=='metadata' and name.lower() not in ('content-type','content-length','server','cache-control','allow','strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','access-control-allow-origin','access-control-allow-credentials'):
            value='[not collected in metadata mode]'
        result.append({'name':name,'value':value})
    return result


def message_excerpt(message, mode):
    if not isinstance(message,dict):raise ImportProblem('HTTP message must be an object.')
    result={k:message[k] for k in ('method','status','bytes','body_sha256','message_sha256','truncated','error','digest_scope') if k in message}
    if 'url' in message:result['url']=safe_url(message['url'])
    result['headers']=safe_headers(message.get('headers',[]),mode)
    if mode=='redacted':
        body=message.get('body','')
        if not isinstance(body,str):raise ImportProblem('Message excerpt must be text.')
        body=re.sub(r'(?im)^(authorization|proxy-authorization|cookie|set-cookie)\s*:[^\r\n]*',r'\1: [redacted]',body)
        body=re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*','Bearer [redacted]',body)
        # Structured JSON/form values with sensitive names never become retained secrets.
        body=re.sub(r'(?i)(["\']?(?:password|passwd|secret|token|api.?key|csrf|session)["\']?\s*[:=]\s*)["\']?[^\s,;&<>"\']+',r'\1[redacted]',body)
        def hidden_input(match):
            tag=match.group()
            if re.search(r'(?i)\btype\s*=\s*["\']?hidden\b',tag) or re.search(r'(?i)\bname\s*=\s*["\']?[^\s>]*?(?:password|secret|token|csrf|session)',tag):
                tag=re.sub(r'(?i)(\bvalue\s*=\s*)("[^"]*"|\'[^\']*\'|[^\s>]+)',r'\1"[redacted]"',tag)
            return tag
        body=re.sub(r'(?i)<input\b[^>]*>',hidden_input,body)
        result['body']=clean(body)[:MAX_TEXT]
        result['excerpt_truncated']=len(body)>MAX_TEXT or bool(message.get('truncated')) or bool(message.get('excerpt_truncated'))
    else:result['body']='[not collected: metadata mode]'
    return result


def normalize(text,context,source):
    data=parse_json(text)
    if not isinstance(data,dict) or data.get('format')!='atlas-web/1':raise ImportProblem('Expected atlas-web/1.')
    mode=data.get('capture_mode','metadata')
    if mode not in ('metadata','redacted'):raise ImportProblem('Capture mode must be metadata or redacted.')
    b=Bundle(source,context);b.source_version=clean(data.get('tool_version','unknown'));b.adapter_version='4'
    events=items(data.get('events',[]),'events')
    if not 1<=len(events)<=100:raise ImportProblem('Web batches require 1–100 events.')
    if len(events)==1:
        if not re.fullmatch(r'[A-Za-z0-9._:-]{1,160}',str(events[0].get('id',''))):raise ImportProblem('A single web event requires a stable event ID.')
        b.event_id=events[0]['id']
    b.warnings.append('Web evidence is a bounded normalized excerpt. Query values and sensitive headers are withheld; bodies are optional best-effort redacted text. Keep protected originals in the source tool. A path or response is not validated exploitation.')
    for i,event in enumerate(events):
        if not isinstance(event,dict):raise ImportProblem('Web event must be an object.')
        url=event.get('url') or (event.get('request') or {}).get('url')
        origin,path,query,host,port=web_url(url)
        when=timestamp(event.get('captured_at'))
        basis='passive' if source in ('web-proxy','web-browser') else 'active test'
        loc=f'events[{i}]'
        device=b.entity('host:'+host,host,'device')
        transport='udp (QUIC)' if event.get('http_version')=='HTTP/3' else 'tcp'
        service=b.entity('service:'+origin+(':quic' if transport!='tcp' else ''),f'{port}/'+transport+' '+urlsplit(origin).scheme,'service')
        app=b.entity('origin:'+origin,origin,'web origin')
        resource=b.entity('resource:'+origin+path,origin+clean(path),'web resource')
        response=event.get('response')
        status='observed' if (isinstance(response,dict) and response.get('status')) or event.get('websocket') else 'unknown'
        b.obs(device,'web service association',{'origin':origin,'limit':'Logical HTTP service context, not physical topology.'},loc,status,basis,target=service,time=when)
        b.obs(service,'web origin',{'origin':origin},loc,status,basis,target=app,time=when)
        b.obs(app,'web resource',{'url':safe_url(url),'method':(event.get('request') or {}).get('method','unknown'),'http_status':response.get('status') if response else None},loc,status,basis,target=resource,time=when)
        request=event.get('request',{})
        parameters=[{'name':name,'location':'query'} for name,_ in parse_qsl(query,keep_blank_values=True,max_num_fields=100)]
        content_type=next((h.get('value','') for h in request.get('headers',[]) if isinstance(h,dict) and h.get('name','').lower()=='content-type'),'')
        request_body=request.get('body','')
        if isinstance(request_body,str):
            try:
                if 'application/x-www-form-urlencoded' in content_type:parameters.extend({'name':name,'location':'form'} for name,_ in parse_qsl(request_body,keep_blank_values=True,max_num_fields=100))
                elif 'application/json' in content_type and request_body:
                    obj=parse_json(request_body)
                    if isinstance(obj,dict):parameters.extend({'name':name,'location':'JSON body'} for name in list(obj)[:100])
            except (ImportProblem,ValueError):b.warnings.append('Request body parameter extraction was incomplete (malformed/truncated/unsupported body).')
        for p in items(event.get('parameters',[]),'parameters'):
            if not isinstance(p,dict) or not isinstance(p.get('name'),str):raise ImportProblem('Invalid web parameter.')
            parameters.append({'name':clean(p['name'])[:200],'location':clean(p.get('location','unknown'))[:80]})
        for p in parameters[:100]:
            param=b.entity('parameter:'+origin+path+':'+p['location']+':'+p['name'],p['name']+' · '+p['location'],'web parameter')
            b.obs(resource,'web parameter',p,loc,basis=basis,target=param,time=when)
        if request:b.obs(resource,'HTTP request',message_excerpt(request,mode),loc+'/request',basis=basis,time=when)
        if response:
            if not isinstance(response.get('status'),int) or not 100<=response['status']<=599:raise ImportProblem('Invalid HTTP response status.')
            b.obs(resource,'HTTP response',message_excerpt(response,mode),loc+'/response',basis=basis,time=when)
        if event.get('error'):b.obs(resource,'web request failure',{'error':clean(event['error'])},loc,'unknown',basis,time=when)
        if event.get('interception'):b.obs(resource,'live request interception',event['interception'],loc,basis='manual',time=when)
        if event.get('test'):b.obs(resource,'selected parameter test',event['test'],loc,basis='active test',time=when)
        if event.get('websocket'):
            ws=event['websocket']
            if not isinstance(ws,dict) or ws.get('direction') not in ('to server','from server') or ws.get('opcode') not in ('text','binary'):raise ImportProblem('Invalid WebSocket message evidence.')
            metadata={k:ws[k] for k in ('connection_id','direction','opcode','bytes','message_sha256','encoding','original_message_sha256','forwarded','limit') if k in ws}
            metadata['body']='[binary message withheld]' if ws['opcode']=='binary' else message_excerpt({'body':ws.get('body',''),'headers':[]},mode)['body']
            b.obs(resource,'WebSocket message',metadata,loc,basis=basis,time=when)
        if event.get('out_of_band'):b.obs(resource,'out-of-band interaction',event['out_of_band'],loc,basis='active test',time=when)
        if event.get('authentication'):
            auth=event['authentication']
            if not isinstance(auth,dict):raise ImportProblem('Authentication evidence must be an object.')
            b.obs(resource,'web authentication context',{k:auth[k] for k in ('mode','session_verified','purpose','generation') if k in auth},loc,basis='active test',time=when)
        if event.get('connected_address'):b.obs(resource,'HTTP transport observation',{'connected_address':event['connected_address'],'elapsed_ms':event.get('elapsed_ms'),'upstream_tls':event.get('upstream_tls'),'http_version':event.get('http_version'),'peer_validation':event.get('peer_validation'),'peer_certificate_sha256':event.get('peer_certificate_sha256'),'source_capture_id':event.get('source_capture_id',event.get('id')),'limit':'One scoped transport observation, not identity proof. HTTPS upstream hostname/CA checks remain enabled. Check derivations share source capture IDs and are not additional requests.'},loc,basis=basis,time=when)
        for link in items(event.get('links',[]),'links')[:100]:
            if not isinstance(link,dict):raise ImportProblem('Invalid web link.')
            target_url=safe_url(link.get('url'))
            target=b.entity('link:'+target_url,target_url,'web resource')
            b.obs(resource,'reported web link',{'url':target_url,'kind':clean(link.get('kind','link')),'limit':'Reported reference; not proof of a fetched or existing resource.'},loc,'unknown',basis,target=target,time=when)
        issue=event.get('issue')
        if issue:
            if not isinstance(issue,dict):raise ImportProblem('Invalid web check issue.')
            b.finding(resource,issue.get('name','Atlas web check'),str(issue.get('severity','unknown')).lower(),issue.get('detail',''),loc+'/issue',issue.get('type','Atlas check'),when)
            b.obs(resource,'web check confidence',{'confidence':clean(issue.get('confidence','unknown')),'limit':'Tool-reported indicator; validate separately.'},loc+'/issue',basis=basis,time=when)
    return b
