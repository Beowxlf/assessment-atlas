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
        self.proxy=Proxy(tools,workspace,{**config,'browser_owned':True});self.tools=tools;self.workspace=workspace;self.error=None;self.ipc_lock=threading.Lock();self.snapshot_lock=threading.Lock();self.snapshot_ready=threading.Event();self.snapshot_id=None;self.snapshot_cookies=[]
        try:
            flags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0
            self.process=subprocess.Popen([node,str(Path(__file__).parent/'browser_session.cjs')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',env=environment,creationflags=flags)
            settings={'url':config['url'],'origins':self.proxy.scope.origins,'excluded':self.proxy.scope.excluded,'port':self.proxy.server.server_address[1],'password':self.proxy.token,'ca_spki':self.proxy.certificates.spki,'headless':config.get('headless') is True}
            self.process.stdin.write(json.dumps(settings)+'\n');self.process.stdin.flush()
            threading.Thread(target=self._watch,daemon=True).start()
            threading.Thread(target=self._deadline,daemon=True).start()
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
            except ValueError:pass
        self.process.wait()
        self.proxy.close('Browser startup failed' if self.error else 'Browser closed')

    def _deadline(self):
        while self.process.poll() is None and not self.proxy.closed:
            __import__('time').sleep(.25)
        if self.process.poll() is None:self.stop()

    def status(self):return {'id':self.proxy.run['id'],'state':'running' if self.process.poll() is None and not self.proxy.closed else 'stopped','error':self.error,'isolated':True,'proxy':self.proxy.status()}

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
