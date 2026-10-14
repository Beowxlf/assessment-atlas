"""Owner-bound Linux PTYs; explicit shell access and bounded typed discovery."""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from .host_operations import PROFILES, command, operation, plan_digest, scope_config, terminal_text
from .importers import ImportProblem, MAX_BYTES, xml
from .store import now


def route_to(target, interface):
    result=subprocess.run(['/usr/sbin/ip' if Path('/usr/sbin/ip').exists() else '/usr/bin/ip','-j','route','get',target],capture_output=True,check=True,timeout=5,text=True)
    if len(result.stdout)>65536:raise ImportProblem('Route response exceeded limits.')
    routes=json.loads(result.stdout)
    if not isinstance(routes,list) or len(routes)!=1 or routes[0].get('dev')!=interface or routes[0].get('type') in ('unreachable','prohibit','blackhole'):
        raise ImportProblem('Target route does not use the selected VPN interface. Connect the VPN on this execution host first.')
    return {'target':target,'interface':interface,'source':str(routes[0].get('prefsrc',routes[0].get('src','unknown')))[:80]}


class Terminal:
    def __init__(self,manager,workspace,owner,config,argv=None,plan=None):
        if not sys.platform.startswith('linux'):raise ImportProblem('Embedded terminals require the Linux execution host. Existing local import/web tools remain available.')
        if os.geteuid()==0:raise ImportProblem('Run Atlas as an unprivileged account; root terminals are refused.')
        import pty,fcntl,termios,struct
        self.manager,self.workspace,self.owner=manager,workspace,owner
        self.lock=threading.RLock();self.buffer=bytearray();self.offset=0;self.closed=False;self.stopping=False;self.stopped=threading.Event();self.last_seen=time.monotonic();self.started=self.last_seen
        self.plan=plan;self.route=None;self.reason='';self.exit_code=None
        if plan:self.route=route_to(plan['target'],plan['interface'])
        self.run=manager.store.start_web_run(workspace,'terminal-operation' if plan else 'terminal-session',{'vantage':'Atlas Linux server terminal','operation':plan or 'Interactive operator shell; scope is operator controlled.','limit':'Raw PTY/input is transient. Only explicitly selected evidence is retained; shell privileges are those of the Atlas account.'})
        self.id=self.run['id'];self.cwd=manager.root/workspace/self.id;self.cwd.mkdir(parents=True,mode=0o700,exist_ok=False)
        self.artifact=self.cwd/'result.txt'
        if plan:
            descriptor=os.open(self.artifact,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(descriptor)
            argv=command(plan,self.artifact)
        self.master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,100,0,0))
        environment={'PATH':'/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(self.cwd),'LANG':'C.UTF-8','TERM':'xterm-256color','PS1':'atlas> '}
        try:
            self.process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('terminal_worker.py')),*(argv or ['/bin/bash','--noprofile','--norc','-i'])],stdin=slave,stdout=slave,stderr=slave,cwd=self.cwd,env=environment,start_new_session=True,close_fds=True)
        except OSError:
            os.close(self.master);manager.store.update_web_run(workspace,self.id,state='failed',ended_at=now(),reason='Terminal executable could not start.');raise ImportProblem('Terminal executable is missing or could not start.') from None
        finally:os.close(slave)
        manager.store.update_web_run(workspace,self.id,state='running')
        threading.Thread(target=self.read,daemon=True).start();threading.Thread(target=self.watch,daemon=True).start()

    def read(self):
        try:
            while True:
                data=os.read(self.master,4096)
                if not data:break
                with self.lock:
                    self.buffer.extend(data)
                    if len(self.buffer)>524288:
                        removed=len(self.buffer)-524288;del self.buffer[:removed];self.offset+=removed
        except OSError:pass
        self.process.wait()
        with self.lock:self.exit_code=self.process.returncode
        if self.plan and not self.closed and not self.stopping:self.intake()
        self.stop('Process exited.',completed=self.process.returncode==0)

    def intake(self):
        try:
            if self.process.returncode!=0:return
            if not self.artifact.is_file() or not 0 < self.artifact.stat().st_size <= MAX_BYTES:raise ImportProblem('Operation returned no bounded importable artifact.')
            content=self.artifact.read_text(encoding='utf-8')
            if self.plan['profile']=='http-headers':
                content=json.dumps({'format':'atlas-evidence/1','source_version':'curl header inspection','entities':[{'key':'target','label':self.plan['target'],'addresses':[self.plan['target']]}],'observations':[{'subject':'target','kind':'HTTP header response','status':'observed','basis':'active test','value':{'url':self.plan['url'],'headers':terminal_text(content),'route':self.route}}],'findings':[]})
                source='atlas'
            else:
                root=xml(content)
                if root.tag!='nmaprun' or any(not any(a.get('addrtype')=='ipv4' and a.get('addr')==self.plan['target'] for a in host.findall('address')) or any(a.get('addrtype')=='ipv4' and a.get('addr')!=self.plan['target'] for a in host.findall('address')) for host in root.findall('host')):raise ImportProblem('Nmap output is outside the exact target scope.')
                finished=root.find('runstats/finished')
                if not root.findall('host') or finished is None or finished.get('exit')!='success' or any(h.get('timedout')=='true' for h in root.findall('host')):
                    self.reason='Partial Nmap coverage: no complete target result or successful run footer. Retained output does not establish a clean verdict.'
                source='nmap'
            result=self.manager.store.import_file(self.workspace,content,'terminal-'+self.id+('.xml' if source=='nmap' else '.json'),source,{'vantage':'Atlas Linux server via '+self.plan['interface'],'namespace':'htb-lab','collected_at':now()},intake='host live')
            self.manager.store.update_web_run(self.workspace,self.id,import_ids=[result['import']['id']],route=self.route,artifact_sha256=hashlib.sha256(self.artifact.read_bytes()).hexdigest(),raw_reference='Protected Linux terminal output in data/terminal-evidence; not embedded in reports.')
        except (OSError,UnicodeError,ImportProblem,ValueError):
            self.reason=self.reason or 'Result intake failed or was incomplete. Original bounded output remains in the protected terminal evidence folder; no clean verdict.'

    def watch(self):
        last_route=0
        while not self.closed and self.process.poll() is None:
            current=time.monotonic()
            if current-self.last_seen>35:return self.stop('Browser connection lease expired; process group stopped.')
            if current-self.started>(self.plan['timeout'] if self.plan else 1800):return self.stop('Terminal time limit reached; coverage may be incomplete.')
            if self.plan:
                try:
                    if self.artifact.stat().st_size>MAX_BYTES:return self.stop('Tool output exceeded 8 MiB; process stopped.')
                    if current-last_route>5:route_to(self.plan['target'],self.plan['interface']);last_route=current
                except (OSError,ValueError,subprocess.SubprocessError):return self.stop('VPN route check failed; operation stopped.')
            self.manager.closed.wait(.25)
            if self.manager.closed.is_set():return self.stop('Atlas stopped.')

    def status(self,cursor=0):
        if isinstance(cursor,bool) or not isinstance(cursor,int) or cursor<0:raise ImportProblem('Invalid terminal output cursor.')
        with self.lock:
            self.last_seen=time.monotonic();start=max(self.offset,min(cursor,self.offset+len(self.buffer)));data=bytes(self.buffer[start-self.offset:start-self.offset+65536])
            return {'id':self.id,'state':'stopped' if self.closed else 'running','data':base64.b64encode(data).decode(),'cursor':start+len(data),'truncated':cursor<self.offset,'reason':self.reason,'exit_code':self.exit_code,'profile':self.plan,'vantage':'Atlas Linux server','route':self.route,'evidence_run':self.id}

    def input(self,value):
        if not isinstance(value,str) or len(value.encode())>8192 or self.closed:raise ImportProblem('Terminal input is invalid, oversized or stopped.')
        if self.plan and value!='\x03':raise ImportProblem('Configured operations accept only Ctrl+C; use the interactive shell for manual commands.')
        self.last_seen=time.monotonic()
        os.write(self.master,value.encode())

    def resize(self,rows,cols):
        if any(isinstance(x,bool) or not isinstance(x,int) for x in (rows,cols)) or not 10<=rows<=100 or not 20<=cols<=240:raise ImportProblem('Invalid terminal dimensions.')
        if self.closed:return
        import fcntl,termios,struct
        fcntl.ioctl(self.master,termios.TIOCSWINSZ,struct.pack('HHHH',rows,cols,0,0))

    def stop(self,reason='Operator stopped terminal.',completed=False):
        with self.lock:
            if self.closed:return
            waiting=self.stopping
            if not waiting:self.stopping=True;self.reason=self.reason or reason
        if waiting:
            self.stopped.wait(6)
            return
        if self.process.poll() is None:
            try:os.killpg(self.process.pid,signal.SIGTERM);self.process.wait(timeout=2)
            except (OSError,subprocess.TimeoutExpired):
                try:os.killpg(self.process.pid,signal.SIGKILL)
                except OSError:pass
                self.process.wait(timeout=3)
        self.exit_code=self.process.returncode
        try:os.close(self.master)
        except OSError:pass
        try:self.manager.store.update_web_run(self.workspace,self.id,state='completed' if completed and not self.reason.startswith(('Result intake','Partial Nmap')) else 'partial' if completed else 'stopped',ended_at=now(),reason=self.reason,exit_code=self.exit_code)
        finally:
            with self.lock:self.closed=True
            self.stopped.set()


class Terminals:
    def __init__(self,store):
        self.store=store;self.sessions={};self.lock=threading.RLock();self.closed=threading.Event();self.root=store.path.parent/'terminal-evidence'

    def capabilities(self):
        import shutil
        return {'linux':sys.platform.startswith('linux'),'unprivileged':sys.platform.startswith('linux') and os.geteuid()!=0,'tools':{name:bool(shutil.which(name)) for name in ('bash','nmap','curl','ip','openvpn')},'profiles':PROFILES,'vantage':'Atlas Linux server; connect HTB VPN here or use SSH manually from the terminal to an authorized execution host.'}

    def get(self,workspace,owner,key):
        session=self.sessions.get(key)
        if not session or session.workspace!=workspace or session.owner!=owner:raise ImportProblem('Terminal is outside this workspace/browser session.')
        return session

    def start(self,workspace,owner,data):
        self.store.get(workspace)
        if data.get('authorized') is not True:raise ImportProblem('Confirm terminal execution authority first.')
        plan=None
        if data.get('operation'):
            scope=scope_config({'targets':[data['operation'].get('target')],'profiles':list(PROFILES),'interface':data.get('interface','tun0')})
            plan=operation(data['operation'],scope)
            if data.get('digest')!=plan_digest(plan):raise ImportProblem('Preview the current operation before starting.')
        request_fingerprint=plan_digest(plan or {'kind':'interactive-shell'})
        with self.lock:
            request=data.get('request_id')
            if not isinstance(request,str) or not __import__('re').fullmatch('[0-9a-f]{32}',request):raise ImportProblem('Use a fresh operation request ID.')
            previous=next((s for s in self.sessions.values() if getattr(s,'request_id',None)==request and s.workspace==workspace and s.owner==owner),None)
            if previous:
                if previous.request_fingerprint!=request_fingerprint:raise ImportProblem('This request ID already identifies a different operation. Use a fresh request ID.')
                return previous.status()
            if len(self.sessions)>=200:raise ImportProblem('Terminal session retention limit reached; restart Atlas to discard closed buffers.')
            if len([s for s in self.sessions.values() if not s.closed])>=2:raise ImportProblem('At most two active terminal sessions; stop one first.')
            session=Terminal(self,workspace,owner,data,plan=plan);session.request_id=request;session.request_fingerprint=request_fingerprint;self.sessions[session.id]=session
            self.store.update_web_run(workspace,session.id,requests=1 if plan and plan['profile']=='http-headers' else None)
            return session.status()

    def preview(self,data):
        scope=scope_config({'targets':[data.get('operation',{}).get('target')],'profiles':list(PROFILES),'interface':data.get('interface','tun0')})
        plan=operation(data.get('operation'),scope)
        return {'plan':plan,'digest':plan_digest(plan),'vantage':'Atlas Linux server','route':route_to(plan['target'],plan['interface']) if sys.platform.startswith('linux') else None,'limits':PROFILES[plan['profile']]['description']}

    def active(self,workspace):return any(s.workspace==workspace and not s.closed for s in self.sessions.values())
    def delete_workspace(self,workspace,confirmation):
        """Confirmed assessment deletion also removes its owned original tool files."""
        import re,shutil
        with self.lock:
            if self.active(workspace):raise ImportProblem('Stop active terminals before deleting this workspace.')
            if not isinstance(workspace,str) or not re.fullmatch('[0-9a-f]{32}',workspace):raise ImportProblem('Invalid workspace evidence path.')
            folder=self.root/workspace
            if folder.is_symlink() or not folder.resolve().is_relative_to(self.root.resolve()) or folder.exists() and not folder.is_dir():raise ImportProblem('Evidence path is unsafe; no files or assessment were deleted.')
            self.store.delete(workspace,confirmation)
            if folder.exists():shutil.rmtree(folder)
            for key,session in list(self.sessions.items()):
                if session.workspace==workspace:
                    with session.lock:session.buffer.clear()
                    del self.sessions[key]
    def close_owner(self,owner):
        for session in list(self.sessions.values()):
            if session.owner==owner:
                session.stop('Operator signed out.')
                with session.lock:session.buffer.clear()
                self.sessions.pop(session.id,None)
    def shutdown(self):
        self.closed.set()
        for session in list(self.sessions.values()):session.stop('Atlas stopped.')
