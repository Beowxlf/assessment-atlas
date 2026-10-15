/* Owned local app only. Exercise the real bundled terminal and browser CSP. */
'use strict';
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const path=require('node:path');
const {spawn}=require('node:child_process');
const root=path.resolve(__dirname,'..');

(async()=>{
  const temporary=path.join(root,'work','test-temp');await fs.mkdir(temporary,{recursive:true});
  const folder=await fs.mkdtemp(path.join(temporary,'csp-ui-'));
  const python=process.env.ATLAS_PYTHON||'python';
  const source="from pathlib import Path; import sys; from atlas.server import AtlasServer; from atlas.store import Store; server=AtlasServer(('127.0.0.1',0),Store(Path(sys.argv[1])/'atlas.sqlite3')); print('http://127.0.0.1:'+str(server.server_port),flush=True); server.serve_forever()";
  const processFixture=spawn(python,['-u','-c',source,folder],{cwd:root,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let browser;let stderr='';processFixture.stderr.on('data',data=>stderr+=data.toString());
  try{
    const url=await new Promise((resolve,reject)=>{let output='';const timer=setTimeout(()=>reject(new Error('CSP fixture did not start: '+stderr)),15000);processFixture.once('error',error=>{clearTimeout(timer);reject(error);});processFixture.once('exit',code=>{clearTimeout(timer);reject(new Error('CSP fixture exited: '+code+' '+stderr));});processFixture.stdout.on('data',data=>{output+=data.toString();const address=output.match(/http:\/\/127\.0\.0\.1:\d+/);if(address){clearTimeout(timer);resolve(address[0]);}});});
    browser=await chromium.launch({channel:process.env.ATLAS_BROWSER_CHANNEL||'msedge',headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',error=>errors.push(error.message));
    await page.addInitScript(()=>{window.cspFixtureViolations=[];document.addEventListener('securitypolicyviolation',event=>window.cspFixtureViolations.push({directive:event.effectiveDirective,blocked:event.blockedURI}));});
    const response=await page.goto(url);const policy=response.headers()['content-security-policy'];
    assert.ok(policy.includes("script-src 'self';"));assert.ok(!policy.includes('unsafe-inline'));assert.ok(!policy.includes('unsafe-eval'));
    await page.waitForFunction(()=>typeof terminalView!=='undefined'&&terminalView&&typeof consoleReady!=='undefined'&&consoleReady);
    await page.evaluate(()=>{show('console');consoleTab('terminal');terminalView.write('SYNTHETIC_CSP_TERMINAL\r\n');});
    await page.locator('#terminal-screen .xterm-rows').filter({hasText:'SYNTHETIC_CSP_TERMINAL'}).waitFor();
    await page.waitForFunction(()=>document.querySelectorAll('#terminal-screen style').length>=2);
    const rendered=await page.evaluate(()=>{
      const nonce=document.querySelector('meta[name="atlas-style-nonce"]').content;
      return{documentProxy:terminalView.options.documentOverride instanceof Document,
        scopedStyles:[...document.querySelectorAll('#terminal-screen style')].map(style=>({nonce:style.nonce===nonce,rules:style.sheet?.cssRules.length||0})),
        violations:window.cspFixtureViolations.slice()};
    });
    assert.equal(rendered.documentProxy,true);assert.ok(rendered.scopedStyles.length>=2);assert.ok(rendered.scopedStyles.every(style=>style.nonce&&style.rules>0));assert.deepEqual(rendered.violations,[]);assert.deepEqual(errors,[]);
    await page.evaluate(()=>{
      const target=document.createElement('div');target.id='csp-fixture-target';document.body.append(target);
      const style=document.createElement('style');style.textContent='#csp-fixture-target{color:rgb(1, 2, 3)!important}';document.head.append(style);
      const script=document.createElement('script');script.textContent='window.cspFixtureInlineScriptExecuted=true';document.head.append(script);
    });
    await page.waitForFunction(()=>window.cspFixtureViolations.some(event=>event.directive.startsWith('style-src'))&&window.cspFixtureViolations.some(event=>event.directive.startsWith('script-src')));
    const denied=await page.evaluate(()=>({executed:window.cspFixtureInlineScriptExecuted===true,color:getComputedStyle(document.getElementById('csp-fixture-target')).color,violations:window.cspFixtureViolations}));
    assert.equal(denied.executed,false);assert.notEqual(denied.color,'rgb(1, 2, 3)');assert.deepEqual(errors,[]);
    const output=process.env.ATLAS_UI_OUTPUT||path.join(root,'test-results');await fs.mkdir(output,{recursive:true});
    await page.screenshot({path:path.join(output,'terminal-csp.png'),fullPage:true});
    await fs.writeFile(path.join(output,'terminal-csp-verification.json'),JSON.stringify({passed:true,synthetic:true,checks:['fresh per-document style nonce','real bundled terminal renders with scoped nonced styles','terminal initialization has no CSP violation','ordinary inline style remains blocked','inline script remains blocked','no unsafe-inline or unsafe-eval'],rendered,denied},null,2));
    console.log('Terminal rendering and restrictive CSP checks passed.');
  }finally{
    if(browser)await browser.close();
    if(processFixture.pid&&processFixture.exitCode===null){const stopped=new Promise(resolve=>processFixture.once('exit',resolve));processFixture.kill();await stopped;}
    const resolved=path.resolve(folder);if(path.dirname(resolved)!==path.resolve(temporary))throw new Error('Unexpected fixture cleanup path');await fs.rm(resolved,{recursive:true,force:true});
  }
})().catch(error=>{console.error(error);process.exitCode=1;});
