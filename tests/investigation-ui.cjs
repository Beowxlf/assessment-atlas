/* Synthetic operator walkthrough: question -> authenticated test -> evidence -> finding -> resume. */
'use strict';
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http');
const go=require('./ui-navigation.cjs');
let stage='setup',browser,target,page;
(async()=>{
  const base=(process.env.ATLAS_UI_URL||'http://127.0.0.1:8787').replace(/\/$/, '');
  const output=process.env.ATLAS_UI_OUTPUT||path.join(__dirname,'../work/investigation-ui-results');
  await fs.mkdir(output,{recursive:true});
  const cookie='investigation-browser-cookie-SYNTHETIC-ONLY',marker='INVESTIGATION_UI_SIGNED_IN',seen=[];
  target=http.createServer((request,response)=>{
    const signed=(request.headers.cookie||'').includes(cookie);seen.push({path:request.url,signed});
    let status=200,body='Synthetic public baseline';
    if(request.url==='/guard'){status=signed?200:401;body=signed?marker:'Sign-in required';}
    if(request.url.startsWith('/private')){status=signed?200:401;body=signed?'SYNTHETIC_OWNED_UI_RECORD':'Sign-in required';}
    response.writeHead(status,{'Content-Type':'text/html; charset=utf-8'});response.end(body);
  });
  await new Promise(resolve=>target.listen(0,'127.0.0.1',resolve));
  const url='http://127.0.0.1:'+target.address().port;
  browser=await chromium.launch({channel:'msedge',headless:true});
  page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[],external=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith(base+'/')&&!/^(blob:|data:)/.test(request.url()))external.push(request.url());});
  const model=id=>page.evaluate(async id=>(await fetch('/api/workspace?id='+id)).json(),id);
  async function mutate(action,button){
    const response=page.waitForResponse(r=>r.url().endsWith('/api/investigation/'+action)&&r.request().method()==='POST');
    await button.click();const result=await response;assert.equal(result.status(),200,await result.text());return result.json();
  }
  async function select(id){await page.locator('#investigation-list [data-investigation="'+id+'"]').click();}
  await page.goto(base);await page.locator('#investigations').waitFor({state:'attached'});
  await page.locator('#new-workspace').click();await page.locator('#new-name').fill('Synthetic resumable investigation UI '+Date.now());
  await page.locator('#new-scope').fill('Owned loopback authentication fixture only; invented credentials and evidence.');
  await page.locator('#new-form .primary').click();await page.locator('#new-dialog').waitFor({state:'hidden'});
  const workspace=await page.locator('#workspace').inputValue();

  stage='save a persistent question';await go(page,'investigations');await page.locator('#investigation-new').click();
  await page.locator('#investigation-question').fill('Does this controlled record require sign-in?');
  await page.locator('#investigation-objective').fill('Document the observed boundary without assuming authorization impact.');
  await page.locator('#investigation-status').selectOption('in progress');
  await page.locator('#investigation-rationale').fill('Compare one owned record with a verified fixture identity.');
  await page.locator('#investigation-next_action').fill('Run the bounded authenticated baseline and inspect evidence.');
  await page.locator('#investigation-access_mode').selectOption('authenticated');
  await page.locator('#investigation-access_role').fill('Synthetic auditor');await page.locator('#investigation-access_reference').fill('ref:synthetic-auditor');
  let saved=await mutate('save',page.locator('#investigation-save'));
  const first=saved.investigation_result_id||saved.investigations.at(-1).id;
  await page.locator('#investigation-save-state').filter({hasText:'Saved draft'}).waitFor();
  await page.reload();await go(page,'overview');
  await page.locator('#investigation-continuation').getByRole('button',{name:'Resume investigation',exact:true}).first().click();
  assert.equal(await page.locator('#investigation-question').inputValue(),'Does this controlled record require sign-in?');
  assert.equal(await page.locator('#investigation-access_reference').inputValue(),'ref:synthetic-auditor');
  assert.match(await page.locator('#investigation-context-note').innerText(),/re.establish|fresh|not.*session|metadata/i);
  assert.equal(seen.length,0,'Restoring a saved investigation must not contact its target');

  stage='durable autosave and optimistic revision conflict recovery';
  const autosaved=page.waitForResponse(r=>r.url().endsWith('/api/investigation/save')&&r.request().method()==='POST');
  await page.locator('#investigation-next_action').fill('Review the bounded baseline before drawing a conclusion.');
  assert.equal((await autosaved).status(),200);await page.reload();await go(page,'investigations');await select(first);
  assert.equal(await page.locator('#investigation-next_action').inputValue(),'Review the bounded baseline before drawing a conclusion.');
  const remote=(await model(workspace)).investigations.find(row=>row.id===first);
  await page.evaluate(async data=>api('investigation/save',data),{workspace,id:first,revision:remote.revision,rationale:'Saved interpretation from a second synthetic tab.'});
  await page.locator('#investigation-rationale').fill('Local unsaved interpretation must survive a revision conflict.');
  const conflict=page.waitForResponse(r=>r.url().endsWith('/api/investigation/save')&&r.request().method()==='POST');
  await page.locator('#investigation-save').click();assert.equal((await conflict).status(),400);
  await page.locator('#investigation-save-state').filter({hasText:/failed/i}).waitFor();
  assert.equal(await page.locator('#investigation-rationale').inputValue(),'Local unsaved interpretation must survive a revision conflict.');
  await page.locator('#investigation-compare-saved').click();await page.locator('#detail-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#detail-body').innerText(),/Local unsaved interpretation/);
  assert.match(await page.locator('#detail-body').innerText(),/Saved interpretation from a second synthetic tab/);
  await page.locator('#close-detail').click();await page.locator('#investigation-reload-saved').click();
  await page.waitForFunction(()=>document.getElementById('investigation-rationale').value==='Saved interpretation from a second synthetic tab.');

  stage='first workbench transition clears an existing authenticated context before asynchronous refresh';
  await go(page,'web');await page.evaluate(()=>webRefresh(true));
  await page.locator('#web-url').fill(url+'/private/record');await page.locator('#web-authorized').check();
  if(await page.locator('#web-auth-toggle').getAttribute('aria-expanded')==='false')await page.locator('#web-auth-toggle').click();
  await page.locator('#web-auth-check').fill(url+'/guard');await page.locator('#web-auth-marker').fill(marker);
  const priorCredentials=page.locator('details').filter({has:page.locator('#web-auth-headers')});
  if(!await priorCredentials.evaluate(element=>element.open))await priorCredentials.locator('summary').click();
  await page.locator('#web-auth-headers').fill('Cookie: session='+cookie);await page.locator('#web-session-save').click();
  await page.locator('#web-session-result').filter({hasText:'Session kept'}).waitFor();
  const previousSession=await page.locator('#web-session').inputValue();assert(previousSession);
  await page.locator('#web-auth-headers').fill('Cookie: old-draft=synthetic-previous-context');
  await page.locator('#web-auth-steps').fill('[{"url":"'+url+'/unused-prior-login","method":"GET"}]');
  await page.locator('[data-web-tab="request"]').click();
  await page.locator('#web-headers').fill('Authorization: Bearer synthetic-previous-request-context');
  await page.locator('#web-body').fill('synthetic prior request body');
  await page.locator('[data-web-tab="scanner"]').click();
  assert.equal(await page.locator('#web-authorized').isChecked(),true);
  assert.equal(await page.locator('#web-session').inputValue(),previousSession);
  assert.equal(seen.length,0,'Keeping a session draft must not contact the fixture');
  await go(page,'investigations');await select(first);await page.evaluate(()=>webPollDone);
  assert.equal(await page.locator('#web-pane-scanner').getAttribute('hidden'),null,'Prior scanner panel must remain selected to expose the timing regression');
  let releaseRefresh,heldRefresh;const refreshGate=new Promise(resolve=>releaseRefresh=resolve);
  const refreshHeld=new Promise(resolve=>heldRefresh=resolve);
  await page.route('**/api/web/status?*',async route=>{const response=await route.fetch();heldRefresh();await refreshGate;await route.fulfill({response});});
  await page.evaluate(()=>{
    window.investigationFirstTransition=null;
    const workbench=document.getElementById('web');
    window.investigationTransitionObserver=new MutationObserver(()=>{
      if(workbench.hidden||window.investigationFirstTransition)return;
      const value=id=>document.getElementById(id).value;
      window.investigationFirstTransition={session:value('web-session'),authorized:document.getElementById('web-authorized').checked,
        headers:value('web-headers'),body:value('web-body'),authHeaders:value('web-auth-headers'),authSteps:value('web-auth-steps'),
        scannerSelected:!document.getElementById('web-pane-scanner').hidden};
    });
    window.investigationTransitionObserver.observe(workbench,{attributes:true,attributeFilter:['hidden']});
  });
  try{
    await page.locator('#investigation-prepare').click();
    await page.locator('#web-pane-scanner').waitFor({state:'visible'});await refreshHeld;
    await page.waitForFunction(()=>window.investigationFirstTransition!==null);
    assert.deepEqual(await page.evaluate(()=>window.investigationFirstTransition),
      {session:'',authorized:false,headers:'',body:'',authHeaders:'',authSteps:'',scannerSelected:true},
      'First visible workbench state must already be cleared while its status refresh is still blocked');
    assert.equal(seen.length,0,'Preparing the investigation must not send target traffic');
  }finally{
    releaseRefresh();await page.unrouteAll({behavior:'wait'});
    await page.evaluate(()=>window.investigationTransitionObserver.disconnect());
  }
  await page.locator('#web-investigation-context').waitFor({state:'visible'});
  await page.locator('#message').filter({hasText:'Investigation test prepared'}).waitFor();
  assert.equal(await page.locator('#web-authorized').isChecked(),false);
  assert.equal(await page.locator('#web-session').inputValue(),'');assert.equal(seen.length,0);
  stage='prepare and deliberately run authenticated baseline';
  await page.locator('#web-url').fill(url+'/private/record');await page.locator('#web-authorized').check();
  await page.locator('#web-limit').fill('20');await page.locator('#web-seconds').fill('30');await page.locator('#web-delay').fill('250');
  if(await page.locator('#web-auth-toggle').getAttribute('aria-expanded')==='false')await page.locator('#web-auth-toggle').click();
  await page.locator('#web-auth-check').fill(url+'/guard');await page.locator('#web-auth-marker').fill(marker);
  const credentials=page.locator('details').filter({has:page.locator('#web-auth-headers')});
  if(!await credentials.evaluate(element=>element.open))await credentials.locator('summary').click();
  await page.locator('#web-auth-headers').fill('Cookie: session='+cookie);await page.locator('#web-session-save').click();
  await page.locator('#web-session-result').filter({hasText:'Session kept'}).waitFor();assert(await page.locator('#web-session').inputValue());
  assert.equal(await page.locator('#web-auth-headers').inputValue(),'','Transient authentication headers must clear after keeping the session');
  await page.locator('[data-web-tab="scanner"]').click();await page.locator('#web-audit-crawl').uncheck();
  await page.locator('#web-active-audit').uncheck();await page.locator('#web-checks input[value="passive"]').check();
  const started=page.waitForResponse(r=>r.url().endsWith('/api/web/start')&&r.request().method()==='POST');
  await page.locator('#web-scanner-start').click();const response=await started;assert.equal(response.status(),200,await response.text());const run=await response.json();
  let completed;const deadline=Date.now()+30000;
  while(Date.now()<deadline){const view=await model(workspace);completed=view.web_runs.find(row=>row.id===run.id);if(completed&&!['running','queued'].includes(completed.state))break;await new Promise(resolve=>setTimeout(resolve,100));}
  assert.equal(completed?.state,'completed');assert(seen.some(row=>row.path==='/private/record'&&row.signed));

  stage='link selected evidence with provenance';await go(page,'investigations');
  await page.locator('#investigation-refresh').click();
  await page.waitForFunction(id=>state.web_runs.some(row=>row.id===id),run.id);await select(first);
  let view=await model(workspace);assert(view.investigations.find(row=>row.id===first).tests.some(row=>row.run_id===run.id));
  const recordSubjects=new Set(view.entities.filter(row=>row.label.endsWith('/private/record')).map(row=>row.id));
  const observation=view.observations.find(row=>recordSubjects.has(row.subject)&&row.kind==='HTTP response'&&row.value.status===200);assert(observation);
  await page.locator('#investigation-observation').selectOption(observation.id);await page.locator('#investigation-relation').selectOption('supporting');
  const linkRevision=view.investigations.find(row=>row.id===first).revision;
  await page.evaluate(async data=>api('investigation/save',data),{workspace,id:first,revision:linkRevision,rationale:'Saved interpretation changed while another tab prepared an evidence link.'});
  const staleLink=page.waitForResponse(r=>r.url().endsWith('/api/investigation/evidence')&&r.request().method()==='POST');
  await page.locator('#investigation-link-evidence').click();assert.equal((await staleLink).status(),400);
  await page.locator('#investigation-compare-saved').waitFor({state:'visible'});
  assert.equal((await model(workspace)).investigations.find(row=>row.id===first).evidence_refs.length,0);
  await page.locator('#investigation-compare-saved').click();await page.locator('#detail-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#detail-body').innerText(),/changed while another tab prepared an evidence link/);
  await page.locator('#close-detail').click();await page.locator('#investigation-reload-saved').click();
  await page.waitForFunction(()=>document.getElementById('investigation-rationale').value==='Saved interpretation changed while another tab prepared an evidence link.');
  await page.locator('#investigation-observation').selectOption(observation.id);await page.locator('#investigation-relation').selectOption('supporting');
  let enteredResolve;const entered=new Promise(resolve=>enteredResolve=resolve);
  await page.route('**/api/investigation/evidence',async route=>{enteredResolve();await new Promise(resolve=>setTimeout(resolve,1800));await route.continue();});
  const linking=mutate('evidence',page.locator('#investigation-link-evidence'));await entered;
  const queuedSave=page.waitForResponse(r=>r.url().endsWith('/api/investigation/save')&&r.request().method()==='POST');
  await page.locator('#investigation-rationale').fill('Interpretation edited while linking evidence remains a durable draft.');
  saved=await linking;assert.equal((await queuedSave).status(),200);await page.unroute('**/api/investigation/evidence');
  assert.equal((await model(workspace)).investigations.find(row=>row.id===first).rationale,'Interpretation edited while linking evidence remains a durable draft.');
  assert(saved.investigations.find(row=>row.id===first).evidence_refs.some(row=>row.observation_id===observation.id&&row.relation==='supporting'));
  assert.match(await page.locator('#investigation-linked-evidence').innerText(),/HTTP response|supporting/);
  const inspector=page.locator('#investigation-linked-evidence').getByRole('button').first();
  await inspector.click();await page.locator('#detail-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#detail-dialog').innerText(),new RegExp(observation.id));
  await page.locator('#close-detail').click();

  stage='finding handoff preserves uncertainty and avoids duplicate clicks';
  await page.locator('#investigation-finding-title').fill('Synthetic controlled authentication observation');
  await page.locator('#investigation-finding-details').fill('A verified fixture identity accessed one owned record. Broader authorization impact remains untested.');
  saved=await mutate('finding',page.locator('#investigation-create-finding'));
  const record=saved.records.find(row=>row.id===saved.investigations.find(row=>row.id===first).finding_record_id);assert(record);
  assert.match(record.validation,/operator.authored.*not independently validated/i);
  assert.equal(await page.locator('#investigation-create-finding').isDisabled(),true);
  assert(!JSON.stringify(saved).includes(cookie));
  await page.locator('#investigation-finding-link').getByRole('button',{name:'Open linked finding',exact:true}).click();
  await page.getByRole('heading',{name:'Synthetic controlled authentication observation',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.activeElement.id),'finding-'+record.id);
  await page.reload();await go(page,'investigations');await select(first);
  assert.equal(await page.locator('#investigation-question').inputValue(),'Does this controlled record require sign-in?');
  assert.match(await page.locator('#investigation-linked-evidence').innerText(),/HTTP response|supporting/);
  await page.screenshot({path:path.join(output,'investigation-resumed-desktop.png'),fullPage:true});

  stage='next question and closed negative investigation';
  await page.locator('#investigation-next-question').fill('What access is denied for a second authorized role?');
  saved=await mutate('next',page.locator('#investigation-create-next'));assert.equal(saved.investigations.length,2);
  await page.locator('#investigation-new').click();await page.locator('#investigation-question').fill('Synthetic negative test with bounded scope');
  await page.locator('#investigation-status').selectOption('closed');await page.locator('#investigation-decision').selectOption('refuted');
  await page.locator('#investigation-rationale').fill('Owned fixture baseline refutes only the stated synthetic concern; not an overall clean verdict.');
  saved=await mutate('save',page.locator('#investigation-save'));
  const negative=saved.investigations.find(row=>row.question==='Synthetic negative test with bounded scope');assert.equal(negative.finding_record_id,null);
  await page.reload();await go(page,'investigations');await select(negative.id);assert.equal(await page.locator('#investigation-status').inputValue(),'closed');
  assert.equal(await page.locator('#investigation-decision').inputValue(),'refuted');
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:path.join(output,'investigation-mobile.png'),fullPage:true});
  const redacted=await page.evaluate(async id=>api('export',{workspace:id}),workspace);
  assert(!JSON.stringify(redacted).includes('ref:synthetic-auditor'));assert(!JSON.stringify(redacted).includes('controlled record require sign-in'));
  assert.equal(errors.length,0,errors.join('\n'));assert.equal(external.length,0);
  await fs.writeFile(path.join(output,'investigation-browser-verification.json'),JSON.stringify({passed:true,synthetic:true,
    workspace_id:workspace,run_id:run.id,investigation_id:first,checks:['persistent question and role metadata','reload resume without execution',
    'durable autosave after reload','optimistic revision conflict keeps local edits','compare and explicitly reload saved revision',
    'stale evidence-link mutation exposes comparison and recovery without a lost update',
    'first visible workbench transition clears prior selected auth/session/request context while status refresh is blocked',
    'safe prepared test handoff','real protected-session verification and authenticated baseline','automatic run linkage','selected evidence provenance inspection',
    'autosave waits for slow evidence mutation without losing interpretation',
    'manual finding with proof limits','linked finding handoff focuses the exact saved record','linked next question','closed negative without forced finding',
    'default export redaction','390px layout'],page_errors:errors,external_ui_requests:external,
    limitation:'Synthetic operator walkthrough; server process/session restart is covered separately by test_investigations_api.py.'},null,2));
  console.log('Resumable investigation, authenticated test, evidence and finding UI workflow passed.');
})().catch(async error=>{console.error('Investigation UI failed during '+stage+': '+error.stack);process.exitCode=1;})
  .finally(async()=>{if(browser)await browser.close();if(target)await new Promise(resolve=>target.close(resolve));});
