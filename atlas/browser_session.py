"""An isolated Atlas-owned Edge/Chromium session; no existing profile changes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import uuid

from .importers import ImportProblem
from .web_proxy import Proxy


class BrowserSession:
    def __init__(self,tools,workspace,config):
        dependency=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node'
        node=os.environ.get('ATLAS_NODE') or shutil.which('node') or str(dependency/'bin/node.exe')
        if not Path(node).is_file():raise ImportProblem('Native browser session requires Node.js and Playwright. See docs/web-tools.md; existing browsers are unchanged.')
        environment=os.environ.copy()
        if not environment.get('ATLAS_PLAYWRIGHT_MODULE') and (dependency/'node_modules/playwright').exists():environment['ATLAS_PLAYWRIGHT_MODULE']=str(dependency/'node_modules/playwright')
        self.proxy=Proxy(tools,workspace,{**config,'browser_owned':True},review_config=config);self.tools=tools;self.workspace=workspace;self.error=None;self.ipc_lock=threading.Lock();self.snapshot_lock=threading.Lock();self.snapshot_ready=threading.Event();self.snapshot_id=None;self.snapshot_cookies=[]
        self.embedded=config.get('embedded') is True;self.action_lock=threading.Lock();self.action_ready=threading.Event();self.action_id=None;self.action_result=None;self.last_action=__import__('time').monotonic()
        try:
            flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
            self.process=subprocess.Popen([node,str(Path(__file__).parent/'browser_session.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',env=environment,creationflags=flags)
            settings={'url':config['url'],'origins':self.proxy.scope.origins,'excluded':self.proxy.scope.excluded,'port':self.proxy.server.server_address[1],'password':self.proxy.token,'ca_spki':self.proxy.certificates.spki,'headless':self.embedded or config.get('headless') is True,'embedded':self.embedded,'channel':os.environ.get('ATLAS_BROWSER_CHANNEL','msedge' if os.name=='nt' else 'chromium')}
            self.process.stdin.write(json.dumps(settings)+'\n');self.process.stdin.flush()
            self.threads=[threading.Thread(target=self._watch,daemon=True),threading.Thread(target=self._deadline,daemon=True)]
            for thread in self.threads:thread.start()
        except OSError:
            self.proxy.close('Browser could not start');raise ImportProblem('Node/browser session could not start.') from None

    def _watch(self):
        for line in self.process.stdout:
            try:
                data=json.loads(line)
                if data.get('state')=='failed':self.error=data.get('reason','Browser startup failed')
                if data.get('state')=='blocked':self.tools.store.update_web_run(self.workspace,self.proxy.run['id'],skipped=data.get('count',0))
                if data.get('state')=='cookies' and data.get('id')==self.snapshot_id:
                    self.snapshot_cookies=data.get('cookies',[])[:100];self.snapshot_ready.set()
                if data.get('state')=='action' and data.get('id')==self.action_id:
                    self.action_result=data;self.action_ready.set()
            except ValueError:pass
        self.process.wait()
        self.proxy.close('Browser startup failed' if self.error else 'Browser closed')

    def _deadline(self):
        while self.process.poll() is None and not self.proxy.closed:
            if self.embedded and __import__('time').monotonic()-self.last_action>35:
                self.proxy.close('Embedded browser connection lease expired');break
            __import__('time').sleep(.25)
        if self.process.poll() is None:self.stop()

    def status(self):return {'id':self.proxy.run['id'],'state':'running' if self.process.poll() is None and not self.proxy.closed else 'stopped','error':self.error,'isolated':True,'embedded':self.embedded,'proxy':self.proxy.status()}

    def action(self,data):
        from .web_evidence import safe_url
        if not self.embedded or self.process.poll() is not None or self.proxy.closed:raise ImportProblem('The embedded browser is closed or unavailable.')
        if not isinstance(data,dict):raise ImportProblem('Browser action must be an object.')
        action=data.get('kind')
        if action not in ('screen','navigate','click','text','key','wheel','read'):raise ImportProblem('Unsupported browser action; scripts and arbitrary automation are refused.')
        value={'kind':action}
        if action=='navigate':
            url=data.get('url');self.proxy.scope.check(url);value['url']=url
        if action=='click':
            for key,limit in (('x',1279),('y',799)):
                v=data.get(key)
                if type(v) is not int or not 0<=v<=limit:raise ImportProblem('Browser click is outside the viewport.')
                value[key]=v
        if action=='text':
            if not isinstance(data.get('text'),str) or len(data['text'].encode())>4096:raise ImportProblem('Browser input exceeds 4 KiB.')
            value['text']=data['text']
        if action=='key':
            key=data.get('key')
            if key not in ('Enter','Backspace','Delete','Tab','Shift+Tab','Escape','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','PageUp','PageDown','Control+a','Control+c','Control+v'):raise ImportProblem('Unsupported browser key.')
            value['key']=key
        if action=='wheel':
            if type(data.get('delta')) is not int or not -800<=data['delta']<=800:raise ImportProblem('Invalid scroll distance.')
            value['delta']=data['delta']
        with self.action_lock:
            self.last_action=__import__('time').monotonic();self.action_id=uuid.uuid4().hex;self.action_result=None;self.action_ready.clear()
            with self.ipc_lock:
                self.process.stdin.write(json.dumps({'action':'embedded','id':self.action_id,**value})+'\n');self.process.stdin.flush()
            if not self.action_ready.wait(10):self.action_id=None;raise ImportProblem('Browser action timed out. Check the retained run and retry a screen refresh.')
            result=self.action_result;self.action_id=None;self.action_result=None
            if not result or result.get('error'):raise ImportProblem('Browser action failed or was outside scope.')
            if not isinstance(result.get('image'),str) or len(result['image'])>2*1024*1024:raise ImportProblem('Browser screen exceeded limits.')
            self.evidence_context={'run_id':self.proxy.run['id'],'url':safe_url(result.get('url','')),'screen_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}
            return {'image':result['image'],'url':self.evidence_context['url'],'text':str(result.get('text',''))[:12000],'width':1280,'height':800}

    def snapshot(self):
        if self.process.poll() is not None or self.proxy.closed:raise ImportProblem('The isolated browser is closed.')
        with self.snapshot_lock:
            self.snapshot_id=uuid.uuid4().hex;self.snapshot_ready.clear();self.snapshot_cookies=[]
            with self.ipc_lock:
                self.process.stdin.write(json.dumps({'action':'cookies','id':self.snapshot_id})+'\n');self.process.stdin.flush()
            if not self.snapshot_ready.wait(5):self.snapshot_id=None;raise ImportProblem('Browser cookie snapshot timed out; wait until login has finished.')
            result=self.snapshot_cookies;self.snapshot_cookies=[];self.snapshot_id=None
            if not result:raise ImportProblem('No scoped browser cookies were available; header/token sessions can be entered separately.')
            return result

    def stop(self):
        if self.process.poll() is None:
            try:
                with self.ipc_lock:self.process.stdin.write('{"action":"stop"}\n');self.process.stdin.flush()
                self.process.wait(timeout=5)
            except (OSError,subprocess.TimeoutExpired):self.process.kill();self.process.wait(timeout=5)
        self.proxy.close('Operator stopped isolated browser')

    def wait_closed(self):
        for thread in self.threads:
            if thread is not threading.current_thread():thread.join()
        self.proxy.wait_closed()
