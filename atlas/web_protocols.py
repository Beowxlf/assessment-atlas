"""Pinned, verified, bounded HTTP/2 and HTTP/3 engines (optional libraries)."""
import hashlib
import logging
import socket
import ssl
import time
from urllib.parse import urlsplit

from .importers import ImportProblem
from .web_evidence import web_url


def available():
    import importlib.util
    return {'http2':importlib.util.find_spec('h2') is not None,'http3':importlib.util.find_spec('aioquic') is not None,'websocket':importlib.util.find_spec('wsproto') is not None}


def fields(url,method,headers):
    p=urlsplit(url)
    return [(':method',method),(':scheme',p.scheme),(':authority',p.netloc),(':path',(p.path or '/')+('?' + p.query if p.query else ''))]+[(k.lower(),v) for k,v in headers.items() if k.lower() not in ('connection','host','keep-alive','proxy-connection','transfer-encoding','upgrade')]


def bounded_headers(headers):
    if len(headers)>100 or sum(len(k)+len(v) for k,v in headers)>65536:raise ImportProblem('Protocol response headers exceed limits.')
    status=None;result=[]
    for name,value in headers:
        if isinstance(name,bytes):name=name.decode('ascii');value=value.decode('utf-8',errors='replace')
        if name==':status':status=int(value)
        elif not name.startswith(':'):result.append({'name':name,'value':value})
    if status is None or not 100<=status<=599:raise ImportProblem('Protocol response status is missing or invalid.')
    return status,result


def exchange_h2(scope,url,method,headers,body,timeout,limit):
    try:
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import ResponseReceived,DataReceived,StreamEnded,StreamReset,ConnectionTerminated,PushedStreamReceived
    except ImportError:raise ImportProblem('HTTP/2 requires requirements-protocols.txt in the Python used by Atlas.') from None
    origin,_,_,host,port=web_url(url);address=scope.pins[origin][0];sock=None;started=time.monotonic();raw=bytearray();status=None;response_headers=[];truncated=False;transport={}
    try:
        sock=scope.connect(address,port,timeout)
        if origin.startswith('https:'):
            context=ssl.create_default_context(cadata=scope.ca_pem or None);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.set_alpn_protocols(['h2']);sock=context.wrap_socket(sock,server_hostname=host)
            if sock.selected_alpn_protocol()!='h2':raise ImportProblem('The server did not negotiate HTTP/2; no silent fallback was made.')
            transport={'upstream_tls':sock.version(),'peer_certificate_sha256':hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()}
        conn=H2Connection(H2Configuration(client_side=True,header_encoding='utf-8'));conn.initiate_connection();conn.send_headers(1,fields(url,method,headers),end_stream=not body)
        if body:conn.send_data(1,body,end_stream=True)
        sock.sendall(conn.data_to_send());received=0;finished=False
        while not finished:
            remaining=timeout-(time.monotonic()-started)
            if remaining<=0:raise TimeoutError()
            sock.settimeout(remaining);data=sock.recv(65536)
            if not data:raise ImportProblem('HTTP/2 peer closed an unfinished response.')
            received+=len(data)
            if received>4*1024*1024:raise ImportProblem('HTTP/2 wire limit exceeded.')
            for event in conn.receive_data(data):
                if isinstance(event,ResponseReceived) and event.stream_id==1:status,response_headers=bounded_headers(event.headers)
                elif isinstance(event,DataReceived) and event.stream_id==1:
                    conn.acknowledge_received_data(event.flow_controlled_length,1);raw.extend(event.data[:max(0,limit+1-len(raw))])
                    if len(raw)>limit:truncated=True;finished=True;conn.reset_stream(1);break
                elif isinstance(event,StreamEnded) and event.stream_id==1:finished=True
                elif isinstance(event,(StreamReset,ConnectionTerminated)):raise ImportProblem('HTTP/2 stream was reset or terminated.')
                elif isinstance(event,PushedStreamReceived):conn.reset_stream(event.pushed_stream_id)
            outbound=conn.data_to_send()
            if outbound:sock.sendall(outbound)
        if status is None:raise ImportProblem('HTTP/2 response did not contain status headers.')
        return status,response_headers,bytes(raw[:limit]),truncated,{**transport,'connected_address':address,'http_version':'HTTP/2'}
    finally:
        if sock:sock.close()


def exchange_h3(scope,url,method,headers,body,timeout,limit):
    try:
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.events import HandshakeCompleted,ConnectionTerminated
        from aioquic.h3.connection import H3Connection,H3_ALPN
        from aioquic.h3.events import HeadersReceived,DataReceived
    except ImportError:raise ImportProblem('HTTP/3 requires requirements-protocols.txt in the Python used by Atlas.') from None
    origin,_,_,host,port=web_url(url)
    if not origin.startswith('https:'):raise ImportProblem('HTTP/3 requires an explicitly scoped HTTPS URL.')
    address=scope.pins[origin][0];destination=(address,port,0,0) if ':' in address else (address,port);family=socket.AF_INET6 if ':' in address else socket.AF_INET
    ca=scope.ca_pem.encode() if scope.ca_pem else ''.join(ssl.DER_cert_to_PEM_cert(cert) for cert in scope.tls.get_ca_certs(binary_form=True)).encode()
    config=QuicConfiguration(is_client=True,alpn_protocols=H3_ALPN,server_name=host,cadata=ca,verify_mode=ssl.CERT_REQUIRED,idle_timeout=timeout,max_data=max(262144,limit*2),max_stream_data=max(131072,limit+65536))
    # Peer-supplied close reasons must never become terminal output.
    logger=logging.getLogger('quic')
    if not logger.handlers:logger.addHandler(logging.NullHandler())
    logger.propagate=False
    conn=QuicConnection(configuration=config);http=H3Connection(conn);raw=bytearray();response_headers=[];status=None;handshake=False;sent=False;finished=False;truncated=False;stream_id=None;started=time.monotonic();received=0
    with socket.socket(family,socket.SOCK_DGRAM) as sock:
        scope.check_execution();scope.bind_socket(sock,address)
        sock.connect(destination);conn.connect(destination,now=time.monotonic())
        while not finished:
            scope.check_execution()
            current=time.monotonic()
            if current-started>=timeout:raise TimeoutError()
            for data,target in conn.datagrams_to_send(now=current):
                if target[:2]!=destination[:2]:raise ImportProblem('HTTP/3 address migration outside the pinned peer was blocked.')
                sock.send(data)
            while True:
                event=conn.next_event()
                if event is None:break
                if isinstance(event,ConnectionTerminated):raise ImportProblem('HTTP/3 handshake/stream failed; certificate and hostname checks remain enabled.')
                if isinstance(event,HandshakeCompleted):handshake=True
                for h_event in http.handle_event(event):
                    if getattr(h_event,'stream_id',None)!=stream_id:continue
                    if isinstance(h_event,HeadersReceived):status,response_headers=bounded_headers(h_event.headers)
                    elif isinstance(h_event,DataReceived):
                        raw.extend(h_event.data[:max(0,limit+1-len(raw))])
                        if len(raw)>limit:truncated=True;finished=True;conn.stop_stream(stream_id,0x10c)
                    if getattr(h_event,'stream_ended',False):finished=True
            if handshake and not sent:
                stream_id=conn.get_next_available_stream_id();http.send_headers(stream_id,[(k.encode(),v.encode()) for k,v in fields(url,method,headers)],end_stream=not body)
                if body:http.send_data(stream_id,body,end_stream=True)
                sent=True;continue
            if finished:break
            timer=conn.get_timer();wait=min(.1,timeout-(time.monotonic()-started),max(.001,timer-time.monotonic()) if timer else .1);sock.settimeout(max(.001,wait))
            try:
                data=sock.recv(65536);received+=len(data)
                if received>4*1024*1024:raise ImportProblem('HTTP/3 wire limit exceeded.')
                conn.receive_datagram(data,destination,now=time.monotonic())
            except socket.timeout:pass
            timer=conn.get_timer()
            if timer and timer<=time.monotonic():conn.handle_timer(now=time.monotonic())
        conn.close()
        for data,target in conn.datagrams_to_send(now=time.monotonic()):
            if target[:2]==destination[:2]:sock.send(data)
    if status is None:raise ImportProblem('HTTP/3 response did not contain status headers.')
    return status,response_headers,bytes(raw[:limit]),truncated,{'connected_address':address,'upstream_tls':'TLSv1.3','http_version':'HTTP/3','peer_validation':'CA and original hostname validated by QUIC TLS; no 0-RTT or migration'}
