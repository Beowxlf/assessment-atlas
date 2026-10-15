/* Real operator tasks, draft interruption, and scoped browser navigation. */
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const go=require('./ui-navigation.cjs');
let stage='setup';
(async()=>{
  const base=(process.env.ATLAS_UI_URL||'http://127.0.0.1:8785').replace(/\/$/,'');
  const fixture=process.env.ATLAS_CONSOLE_FIXTURE||'http://127.0.0.1:8779';
  const output=process.env.ATLAS_UI_OUTPUT||path.join(__dirname,'../test-results/qol');
  await fs.mkdir(output,{recursive:true});
  const browser=await chromium.launch({channel:'msedge',headless:true});
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],external=[],starts=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{
    if(!request.url().startsWith(base+'/')&&!request.url().startsWith('data:')&&!request.url().startsWith('blob:'))external.push(request.url());
    if(/\/api\/(terminal\/start|web\/browser\/start|web\/(crawl|scan|scanner)|vulnerability\/scan)$/.test(request.url()))starts.push(request.url());
  });
  async function model(id){return page.evaluate(async id=>(await fetch('/api/workspace?id='+id)).json(),id);}
  async function create(name){
    await page.locator('#new-workspace').click();await page.locator('#new-name').fill(name);
    await page.locator('#new-scope').fill('Synthetic QoL acceptance; only an owned loopback browser fixture is authorized.');
    await page.locator('#new-form .primary').click();await page.locator('#new-dialog').waitFor({state:'hidden'});
    return page.locator('#workspace').inputValue();
  }
  async function importFile(name){await go(page,'import');await page.locator('#import-file').setInputFiles(path.join(__dirname,'../fixtures',name));await page.locator('#import-form .primary').click();await page.getByRole('button',{name:'Save this import',exact:true}).click();await page.getByRole('button',{name:'Save this import',exact:true}).waitFor({state:'detached'});}
  await page.goto(base);await page.locator('#console').waitFor({state:'attached'});
  const first=await create('Synthetic QoL first workspace '+Date.now());
  await importFile('vulnerability-nmap.xml');await importFile('scan.nessus');
  stage='prepared target handoffs';await go(page,'discovery');
  await page.locator('#discovery-targets').getByRole('button',{name:'fixture-only.example.test',exact:true}).click();
  await page.getByRole('button',{name:'Prepare terminal for 192.0.2.80',exact:true}).click();
  await page.locator('#message').filter({hasText:'Terminal prepared for'}).waitFor();
  assert.equal(await page.locator('#console-terminal').isVisible(),true);
  assert.equal(await page.locator('#terminal-target').inputValue(),'192.0.2.80');
  assert.equal(await page.locator('#terminal-profile').inputValue(),'service-enumeration');
  assert.equal(await page.locator('#terminal-ports').inputValue(),'8080');
  assert.equal(await page.locator('#terminal-operation-authorized').isChecked(),false);
  assert.equal(await page.locator('#terminal-authorized').isChecked(),false);
  assert.equal(await page.locator('#terminal-run').isEnabled(),false);
  const chosenSubject=await page.locator('#console-subject').inputValue();assert(chosenSubject);
  await page.screenshot({path:path.join(output,'qol-prepared-terminal.png'),fullPage:true});
  await go(page,'discovery');await page.getByRole('button',{name:'Prepare embedded browser',exact:true}).click();
  await page.locator('#message').filter({hasText:'Embedded browser prepared'}).waitFor();
  assert.equal(await page.locator('#embedded-url').inputValue(),'http://192.0.2.80:8080/');
  assert.equal(await page.locator('#embedded-authorized').isChecked(),false);
  assert.equal(await page.locator('#embedded-controls').isVisible(),false);
  assert.equal(await page.locator('#console-subject').inputValue(),chosenSubject);
  assert.deepEqual(starts,[]);assert.equal((await model(first)).web_runs?.length||0,0);

  stage='keyboard finder and recents';await page.keyboard.press('Control+k');
  await page.locator('#tool-dialog-search').fill('decoder');await page.locator('#tool-dialog-search').press('ArrowDown');
  assert.equal(await page.locator('#tool-dialog-results button').first().evaluate(element=>element===document.activeElement),true);
  await page.keyboard.press('ArrowUp');assert.equal(await page.locator('#tool-dialog-search').evaluate(element=>element===document.activeElement),true);
  await page.keyboard.press('Enter');await page.locator('#web-pane-advanced').waitFor({state:'visible'});
  await go(page,'tools');assert.equal(await page.locator('#recent-tools').getByRole('button',{name:'Decoder',exact:true}).count(),1);
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('no-matching-tool');await page.keyboard.press('Enter');
  assert.equal(await page.locator('#tool-dialog').isVisible(),true);await page.keyboard.press('Escape');

  stage='drafts across views and workspaces';await go(page,'activity');
  await page.locator('#record-kind').selectOption('finding');await page.locator('#record-subject').selectOption(chosenSubject);
  await page.locator('#record-title').fill('Synthetic QoL manual finding');await page.locator('#record-details').fill('Evidence interpretation is unfinished; impact remains unvalidated.');
  await page.locator('#record-evidence').fill('synthetic-protected-reference');await page.locator('#record-status').selectOption('needs retest');
  await go(page,'findings');
  // A review refresh used to reset the unsaved record's identity.
  const review=page.locator('#finding-list .review-form').first();await review.locator('select').selectOption('in progress');await review.locator('input').fill('Synthetic review with preserved draft.');await review.locator('button').click();
  await page.locator('#message').filter({hasText:'Review saved with history'}).waitFor();
  await go(page,'activity');assert.equal(await page.locator('#record-subject').inputValue(),chosenSubject);
  assert.equal(await page.locator('#record-status').inputValue(),'needs retest');
  const second=await create('Synthetic QoL second workspace '+Date.now());await go(page,'activity');
  assert.equal(await page.locator('#record-title').inputValue(),'');await page.locator('#record-title').fill('Separate workspace draft');
  await page.locator('#workspace').selectOption(first);await page.locator('#record-title').waitFor({state:'visible'});
  await page.waitForFunction(()=>document.getElementById('record-title').value==='Synthetic QoL manual finding');
  assert.equal(await page.locator('#record-kind').inputValue(),'finding');assert.equal(await page.locator('#record-subject').inputValue(),chosenSubject);
  assert.equal(await page.locator('#record-evidence').inputValue(),'synthetic-protected-reference');
  await page.locator('#workspace').selectOption(second);await page.waitForFunction(()=>document.getElementById('record-title').value==='Separate workspace draft');
  await page.locator('#workspace').selectOption(first);await page.waitForFunction(()=>document.getElementById('record-title').value==='Synthetic QoL manual finding');
  // A slower earlier workspace response cannot replace the most recent choice.
  let delayedFinished;const delayed=new Promise(resolve=>delayedFinished=resolve);
  await page.route('**/api/workspace?id='+second,async route=>{await new Promise(resolve=>setTimeout(resolve,500));await route.continue();delayedFinished();});
  const oldRequest=page.waitForRequest(request=>request.url().endsWith('/api/workspace?id='+second));
  await page.locator('#workspace').selectOption(second);await oldRequest;await page.locator('#workspace').selectOption(first);
  await delayed;await page.unroute('**/api/workspace?id='+second);
  await page.waitForFunction(id=>state.id===id&&document.getElementById('workspace').value===id,first);
  assert.equal(await page.locator('#record-title').inputValue(),'Synthetic QoL manual finding');

  stage='save shortcut preserves edits during a slow request';
  await page.route('**/api/record',async route=>{await new Promise(resolve=>setTimeout(resolve,450));await route.continue();});
  await page.locator('#record-title').focus();await page.keyboard.press('Control+s');await page.waitForFunction(()=>recordSaving);
  await page.locator('#record-details').fill('Additional edits made while saving must remain an unfinished draft.');
  await page.locator('#message').filter({hasText:'Assessment record saved'}).waitFor();
  assert.equal(await page.locator('#record-details').inputValue(),'Additional edits made while saving must remain an unfinished draft.');
  assert.equal((await model(first)).records.filter(record=>record.title==='Synthetic QoL manual finding').length,1);
  await page.unroute('**/api/record');await page.locator('#record-title').fill('Synthetic QoL additional edits');
  await page.locator('#record-title').press('Control+s');await page.waitForFunction(()=>document.getElementById('record-title').value==='');
  assert.match(await page.locator('#record-draft-status').innerText(),/No unfinished draft/);

  stage='finding filters and source/impact distinctions';await go(page,'findings');
  const saved=await model(first),manualCount=saved.records.filter(record=>record.kind==='finding').length;
  assert.equal(await page.locator('#finding-list .finding-card').count(),saved.findings.length+manualCount);
  await page.locator('#finding-type').selectOption('manual');await page.locator('#finding-status').selectOption('needs retest');
  await page.locator('#finding-severity').selectOption('unrated');await page.locator('#finding-search').fill('additional edits');
  assert.equal(await page.locator('#finding-list .finding-card').count(),1);
  assert.match(await page.locator('#finding-count').innerText(),new RegExp('1 of '+(saved.findings.length+manualCount)+' findings'));
  await page.screenshot({path:path.join(output,'qol-findings.png'),fullPage:true});
  await page.locator('#finding-search').fill('no-such-finding');assert.match(await page.locator('#finding-list').innerText(),/No findings match/);
  await page.locator('#finding-clear').click();assert.equal(await page.locator('#finding-list .finding-card').count(),saved.findings.length+manualCount);
  await page.locator('#finding-type').selectOption('source');assert.equal(await page.locator('#finding-list .finding-card').count(),saved.findings.length);
  const exported=await page.evaluate(async()=>api('export',{workspace:state.id,identifiers:false}));assert.equal(exported.findings.length,saved.findings.length);
  assert.equal(exported.records.filter(record=>record.kind==='finding').length,manualCount);
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),390);
  await page.screenshot({path:path.join(output,'qol-findings-mobile.png'),fullPage:true});await page.setViewportSize({width:1440,height:1000});

  stage='compact scoped browser and explicit navigation';
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('embedded browser');await page.keyboard.press('Enter');
  await page.locator('#console-browser').waitFor({state:'visible'});
  await page.locator('#embedded-url').fill(fixture+'/app/');await page.locator('#embedded-prefix').fill('/app/');await page.locator('#embedded-authorized').check();
  await page.locator('#embedded-start .primary').click();await page.locator('#embedded-screen').waitFor({state:'visible'});
  assert.equal(await page.locator('#embedded-setup').evaluate(element=>element.open),false);
  await page.locator('#embedded-setup summary').click();assert.equal(await page.locator('#embedded-url').isEnabled(),false);
  await page.locator('#embedded-setup summary').click();
  await page.locator('#embedded-location').fill('/app/next?example=synthetic-value');await page.locator('#embedded-navigate button').click();
  await page.locator('#embedded-status').filter({hasText:'/app/next'}).waitFor();assert.doesNotMatch(await page.locator('#embedded-status').innerText(),/synthetic-value/);
  const blocked=page.waitForResponse(response=>response.url().endsWith('/api/web/browser/action')&&response.status()===400);
  await page.locator('#embedded-location').fill('/outside');await page.locator('#embedded-navigate button').click();await blocked;
  assert.equal(await page.locator('#embedded-screen').isVisible(),true);
  await page.locator('#embedded-auth').click();await page.locator('#web-pane-scanner').waitFor({state:'visible'});
  assert.equal(await page.locator('#web-prefix').inputValue(),'/app/');assert.equal(await page.locator('#web-url').inputValue(),fixture+'/app/');
  assert.equal(await page.locator('#web-authorized').isChecked(),false);assert.equal(await page.locator('#web-session').inputValue(),'');
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('embedded browser');await page.keyboard.press('Enter');
  await page.locator('#embedded-read').click();await page.locator('#console-evidence').waitFor({state:'visible'});
  await page.locator('#console-title').fill('Synthetic QoL browser evidence');await page.locator('#console-subject').selectOption(chosenSubject);
  // Evidence handoff must never overwrite an unfinished assessment draft.
  await go(page,'activity');await page.locator('#record-title').fill('Keep this existing draft');
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('evidence to finding');await page.keyboard.press('Enter');
  const observationsBefore=(await model(first)).observations.length;await page.locator('#console-capture .primary').click();
  await page.locator('#activity').waitFor({state:'visible'});assert.equal(await page.locator('#record-title').inputValue(),'Keep this existing draft');
  assert.equal((await model(first)).observations.length,observationsBefore);
  await page.locator('#record-form .primary').click();await page.waitForFunction(()=>document.getElementById('record-title').value==='');
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('evidence to finding');await page.keyboard.press('Enter');
  assert.match(await page.locator('#console-text').inputValue(),/Owned browser fixture/);await page.locator('#console-capture .primary').click();
  await page.locator('#activity').waitFor({state:'visible'});assert.equal(await page.locator('#record-title').inputValue(),'Synthetic QoL browser evidence');
  assert.match(await page.locator('#record-evidence').inputValue(),/^[a-f0-9]{32}$/);await page.locator('#record-form .primary').click();
  await page.waitForFunction(()=>document.getElementById('record-title').value==='');
  await page.keyboard.press('Control+k');await page.locator('#tool-dialog-search').fill('embedded browser');await page.keyboard.press('Enter');
  await page.screenshot({path:path.join(output,'qol-embedded-browser.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),390);
  await page.screenshot({path:path.join(output,'qol-browser-mobile.png'),fullPage:true});await page.locator('#embedded-stop').click();
  await page.locator('#embedded-setup').waitFor({state:'visible'});await page.waitForFunction(()=>!embeddedId);
  assert.equal(await page.locator('#embedded-authorized').isChecked(),false);assert.equal(await page.locator('#embedded-url').isEnabled(),true);
  const storage=await page.evaluate(()=>Object.fromEntries(Object.keys(localStorage).map(key=>[key,localStorage.getItem(key)])));
  assert.doesNotMatch(JSON.stringify(storage),/Additional edits made|Synthetic QoL manual|Separate workspace draft|synthetic-value/);
  assert.equal(starts.length,1);assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
  await fs.writeFile(path.join(output,'qol-browser-verification.json'),JSON.stringify({passed:true,synthetic:true,checks:['target-to-terminal IPv4/open-port preparation without execution','target-to-browser preparation with fresh authorization','finder Enter/arrow keys and local tool-name recents','workspace-isolated transient drafts survive review refresh','save shortcut preserves edits made during a request','manual/source finding search/status/severity filters','filters do not narrow report content','mobile findings/browser reflow','compact browser setup and immutable active scope','deliberate scoped page navigation with outside-path rejection','authenticated handoff retains reviewed path prefix and resets authority','existing draft protected before evidence mutation','direct evidence finding with retained reference','explicit browser stop and restart-ready setup','no draft/target/credential persistence in browser preferences'],automatic_target_operations:0,explicit_owned_browser_sessions:1,page_errors:errors,external_ui_requests:external},null,2));
  await browser.close();console.log('QoL target handoffs, finding filters, draft interruptions and scoped console workflow passed.');
})().catch(error=>{console.error('QoL browser check failed at '+stage+': '+String(error.message).slice(0,1200));process.exit(1);});
