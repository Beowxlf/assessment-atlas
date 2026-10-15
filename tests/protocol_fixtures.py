"""Real owned HTTP/2 TLS, HTTP/3 QUIC and RFC6455 fixture peers."""
import asyncio
import datetime as dt
import socket
import threading
from pathlib import Path

from atlas.web_proxy import LocalCertificates


class ProtocolFixtures:
    def __init__(self,folder):
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import RequestReceived,DataReceived,StreamEnded
        from aioquic.asyncio import serve
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.h3.connection import H3Connection,H3_ALPN
        from aioquic.h3.events import HeadersReceived,DataReceived as H3Data
        self.ca=LocalCertificates();self.closed=False;self.seen=[];self.folder=Path(folder);self.ready=threading.Event();context=self.ca.context('127.0.0.1',self.folder);context.set_alpn_protocols(['h2'])
        self.h2=socket.socket();self.h2.bind(('127.0.0.1',0));self.h2.listen();self.h2.settimeout(.2);self.h2_port=self.h2.getsockname()[1]
        def handle(client):
            try:
                with context.wrap_socket(client,server_side=True) as conn:
                    conn.settimeout(5);h2=H2Connection(H2Configuration(client_side=False,header_encoding='utf-8'));h2.initiate_connection();conn.sendall(h2.data_to_send());rows={}
                    while not self.closed:
                        raw=conn.recv(65536)
                        if not raw:break
                        for event in h2.receive_data(raw):
                            if isinstance(event,RequestReceived):rows[event.stream_id]={'headers':dict(event.headers),'body':b''}
                            elif isinstance(event,DataReceived):rows[event.stream_id]['body']+=event.data;h2.acknowledge_received_data(event.flow_controlled_length,event.stream_id)
                            if isinstance(event,StreamEnded):
                                row=rows[event.stream_id];self.seen.append(('HTTP/2',row));body=row['body'] or ('h2 '+row['headers'][':path']).encode();h2.send_headers(event.stream_id,[(':status','200'),('content-type','text/plain'),('content-length',str(len(body)))]);h2.send_data(event.stream_id,body,end_stream=True)
                        conn.sendall(h2.data_to_send())
            except Exception:client.close()
        def accept():
            while not self.closed:
                try:client,_=self.h2.accept();threading.Thread(target=handle,args=(client,),daemon=True).start()
                except socket.timeout:pass
                except OSError:break
        threading.Thread(target=accept,daemon=True).start()
        owner=self
        class H3Server(QuicConnectionProtocol):
            def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.http=H3Connection(self._quic);self.rows={}
            def quic_event_received(self,event):
                for item in self.http.handle_event(event):
                    if isinstance(item,HeadersReceived):self.rows[item.stream_id]={'headers':dict(item.headers),'body':b''}
                    elif isinstance(item,H3Data):self.rows[item.stream_id]['body']+=item.data
                    if getattr(item,'stream_ended',False) and item.stream_id in self.rows:
                        row=self.rows.pop(item.stream_id);owner.seen.append(('HTTP/3',row));body=row['body'] or b'h3 '+row['headers'][b':path'];self.http.send_headers(item.stream_id,[(b':status',b'200'),(b'content-type',b'text/plain'),(b'content-length',str(len(body)).encode())]);self.http.send_data(item.stream_id,body,end_stream=True);self.transmit()
        x509=self.ca.x509;key=self.ca.rsa.generate_private_key(public_exponent=65537,key_size=2048);now=dt.datetime.now(dt.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(self.ca.NameOID.COMMON_NAME,'127.0.0.1')]))
              .issuer_name(self.ca.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__('ipaddress').ip_address('127.0.0.1'))]),critical=False)
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
              .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=None,decipher_only=None),critical=True)
              .add_extension(x509.ExtendedKeyUsage([self.ca.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca.key.public_key()),critical=False)
              .sign(self.ca.key,self.ca.hashes.SHA256()))
        config=QuicConfiguration(is_client=False,alpn_protocols=H3_ALPN);config.certificate=cert;config.certificate_chain=[self.ca.ca];config.private_key=key
        self.loop=asyncio.new_event_loop()
        async def start():
            self.quic_server=await serve('127.0.0.1',0,configuration=config,create_protocol=H3Server);self.h3_port=self.quic_server._transport.get_extra_info('sockname')[1];self.ready.set()
        def run():asyncio.set_event_loop(self.loop);self.loop.run_until_complete(start());self.loop.run_forever();self.loop.close()
        self.thread=threading.Thread(target=run,daemon=True);self.thread.start();assert self.ready.wait(5)
    def close(self):
        self.closed=True;self.h2.close()
        async def finish():self.quic_server.close();await asyncio.sleep(.1);self.loop.stop()
        asyncio.run_coroutine_threadsafe(finish(),self.loop);self.thread.join(3)


class WebSocketFixture:
    def __init__(self,tls=None,required_token=None):
        import wsproto
        from wsproto import events
        self.closed=False;self.seen=[];self.sock=socket.socket();self.sock.bind(('127.0.0.1',0));self.sock.listen();self.sock.settimeout(.2);self.port=self.sock.getsockname()[1];self.clients=[]
        def handle(sock):
            try:
                if tls:sock=tls.wrap_socket(sock,server_side=True)
                self.clients.append(sock);sock.settimeout(30);ws=wsproto.WSConnection(wsproto.ConnectionType.SERVER)
                while not self.closed:
                    raw=sock.recv(65536)
                    if not raw:break
                    if required_token and raw.startswith(b'GET /guard '):
                        signed=('Authorization: Bearer '+required_token).encode() in raw
                        self.seen.append({'guard':signed})
                        body=b'WS_SIGNED_IN_FIXTURE' if signed else b'login required'
                        sock.sendall(b'HTTP/1.1 '+(b'200 OK' if signed else b'401 Unauthorized')+b'\r\nContent-Type: text/plain\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body);return
                    ws.receive_data(raw)
                    for event in ws.events():
                        if isinstance(event,events.Request):
                            self.seen.append(event)
                            if required_token and not any(k.lower()==b'authorization' and v==('Bearer '+required_token).encode() for k,v in event.extra_headers):sock.sendall(ws.send(events.RejectConnection(status_code=401,has_body=False)));return
                            sock.sendall(ws.send(events.AcceptConnection()))
                        elif isinstance(event,events.TextMessage):self.seen.append(event.data);sock.sendall(ws.send(events.TextMessage(data='echo:'+event.data)))
                        elif isinstance(event,events.BytesMessage):self.seen.append(event.data);sock.sendall(ws.send(events.BytesMessage(data=event.data)))
                        elif isinstance(event,events.Ping):sock.sendall(ws.send(event.response()))
                        elif isinstance(event,events.CloseConnection):return
            except Exception:pass
            finally:sock.close()
        def accept():
            while not self.closed:
                try:sock,_=self.sock.accept();threading.Thread(target=handle,args=(sock,),daemon=True).start()
                except socket.timeout:pass
                except OSError:break
        threading.Thread(target=accept,daemon=True).start()
    def close(self):
        self.closed=True;self.sock.close()
        for sock in self.clients:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            sock.close()
