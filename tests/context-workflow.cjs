/* Execution review and safe interrupted-run recovery, with owned loopback targets. */
'use strict';
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http');
const go=require('./ui-navigation.cjs');
let stage='setup',browser,target;const held=[],sockets=new Set();
(async()=>{
  const base=(process.env.ATLAS_UI_URL||'http://127.0.0.1:8787').replace(/\/$/,'');
  const output=process.env.ATLAS_UI_OUTPUT||path.join(__dirname,'../work/context-workflow-results');
  await fs.mkdir(output,{recursive:true});const seen=[];let connections=0;
  target=http.createServer((request,response)=>{
    seen.push(request.url);if(request.url==='/slow'){held.push(response);return;}
    response.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});response.end('Synthetic owned execution-context baseline');
  });
  target.on('connection',socket=>{connections++;sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolve=>target.listen(0,'127.0.0.1',resolve));const fixture='http://127.0.0.1:'+target.address().port;
  browser=await chromium.launch({channel:'msedge',headless:true});const page=await browser.newPage({viewport:{width:1440,height:1000}});
  const errors=[],starts=[];page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(request.url().endsWith('/api/web/start'))starts.push(request.postDataJSON());});
  const model=id=>page.evaluate(async id=>api('workspace?id='+encodeURIComponent(id)),id);
  async function ended(workspace,id){const deadline=Date.now()+30000;while(Date.now()<deadline){const row=(await model(workspace)).web_runs?.find(row=>row.id===id);if(row&&!['queued','running'].includes(row.state))return row;await new Promise(resolve=>setTimeout(resolve,100));}throw new Error('Synthetic run did not reach an ended state');}
  async function blockedStart(){const count=starts.length;await page.locator('#web-crawl .primary').click();await page.locator('#message').filter({hasText:'Preview execution'}).waitFor();assert.equal(starts.length,count,'The client must not send an unreviewed investigation start');}
  async function review(){const response=page.waitForResponse(r=>r.url().endsWith('/api/execution/preview'));await page.locator('#web-context-preview').click();const result=await response;assert.equal(result.status(),200,await result.text());await page.locator('#web-context-status').filter({hasText:'Ready'}).waitFor();return result.json();}
  async function launch(){const response=page.waitForResponse(r=>r.url().endsWith('/api/web/start'));await page.locator('#web-crawl .primary').click();const result=await response;assert.equal(result.status(),200,await result.text());return result.json();}
  await page.goto(base);await page.locator('#investigations').waitFor({state:'attached'});
  await page.locator('#new-workspace').click();await page.locator('#new-name').fill('Synthetic execution review '+Date.now());
  await page.locator('#new-scope').fill('Owned loopback fixture only; no HTB connectivity claim.');await page.locator('#new-form .primary').click();await page.locator('#new-dialog').waitFor({state:'hidden'});
  const workspace=await page.locator('#workspace').inputValue();
  const status=await page.evaluate(async id=>api('execution/status?workspace='+encodeURIComponent(id)),workspace);
  const expected=status.interfaces.some(row=>row.name==='lo')?'lo':'system';
  stage='save the actual execution host and expected interface';await go(page,'investigations');await page.locator('#investigation-new').click();
  await page.locator('#investigation-question').fill('Can this bounded service investigation be safely continued after interruption?');
  await page.locator('#investigation-interface').selectOption(expected);
  const saved=page.waitForResponse(r=>r.url().endsWith('/api/investigation/save'));
  await page.locator('#investigation-save').click();const first=await(await saved).json();
  const investigation=first.investigations.find(row=>row.id===first.investigation_result_id)||first.investigations.at(-1);
  assert.deepEqual(investigation.execution_context,{host_id:status.host.id,interface:expected});
  await page.locator('#investigation-prepare').click();await page.locator('#web-investigation-context').waitFor({state:'visible'});
  await page.locator('#message').filter({hasText:'Investigation test prepared'}).waitFor();
  assert.equal(await page.locator('#web-interface').inputValue(),expected);assert.equal(await page.locator('#web-interface').isDisabled(),true);
  await page.locator('[data-web-tab="crawl"]').click();await page.locator('#web-url').fill(fixture+'/public?synthetic=PRIVATE_UI_QUERY');
  await page.locator('#web-limit').fill('20');await page.locator('#web-seconds').fill('30');await page.locator('#web-delay').fill('250');
  await page.locator('#web-depth').fill('0');await page.locator('#web-follow').uncheck();
  await page.locator('#web-paths').fill('/slow\n/after-stop');await page.locator('#web-authorized').check();
  stage='current preview is required and configuration edits invalidate it';await blockedStart();
  const preview=await review();assert.equal(connections,0,'Preview may resolve but must not open any target socket');assert.equal(seen.length,0);
  await page.locator('#web-limit').fill('19');await blockedStart();await review();
  await page.locator('#web-url').fill(fixture+'/public?synthetic=CHANGED_PRIVATE_UI_QUERY');
  assert.equal(await page.locator('#web-authorized').isChecked(),false,'A target change must clear prior authorization');await blockedStart();
  await page.locator('#web-url').fill(fixture+'/public?synthetic=PRIVATE_UI_QUERY');await page.locator('#web-authorized').check();await review();
  assert.equal(connections,0);assert.equal(seen.length,0);
  stage='interrupt a real bounded operation and retain its partial observations';const source=await launch();
  const deadline=Date.now()+15000;while(!held.length&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,50));assert(held.length);
  const before=await model(workspace);assert(before.observations.length);
  const stopped=page.waitForResponse(r=>r.url().endsWith('/api/web/stop'));
  await page.locator('#web-runs .list-item').filter({has:page.getByRole('button',{name:'Stop run',exact:true})}).first().getByRole('button',{name:'Stop run',exact:true}).click();
  assert.equal((await stopped).status(),200);for(const response of held.splice(0)){response.writeHead(200,{'Content-Type':'text/plain'});response.end('Synthetic in-flight response after requested stop');}
  const incomplete=await ended(workspace,source.id);assert(['cancelled','partial','interrupted'].includes(incomplete.state),JSON.stringify(incomplete));
  assert(!seen.includes('/after-stop'),'Cancellation must stop the next target request');
  const preserved=await model(workspace),sourceState=preserved.web_runs.find(row=>row.id===source.id);
  assert.equal(preserved.investigations[0].decision,'undecided');
  stage='prepare a separate safe run without restoring old authority or request inputs';
  await go(page,'investigations');await page.locator('#investigation-refresh').click();
  const resume=page.locator('#investigation-linked-runs [data-resume-run="'+source.id+'"]');await resume.waitFor({state:'visible'});
  const callCount=seen.length;await resume.click();await page.locator('#web-investigation-context').filter({hasText:source.id}).waitFor();
  await page.locator('#message').filter({hasText:'Investigation test prepared'}).waitFor();assert.equal(seen.length,callCount);
  assert.equal(await page.locator('#web-authorized').isChecked(),false);assert.equal(await page.locator('#web-session').inputValue(),'');
  for(const id of ['web-headers','web-body','web-paths'])assert.equal(await page.locator('#'+id).inputValue(),'');
  assert.equal(new URL(await page.locator('#web-url').inputValue()).search,'');
  assert(!await page.locator('#web-context-status').innerText().then(text=>text.startsWith('Ready')));
  await page.locator('#web-authorized').check();await blockedStart();const freshReview=await review();assert.equal(seen.length,callCount);
  const next=await launch();assert.notEqual(next.id,source.id);assert.equal((await ended(workspace,next.id)).state,'completed');
  const final=await model(workspace);assert.deepEqual(final.web_runs.find(row=>row.id===source.id),sourceState);
  assert.equal(final.web_runs.find(row=>row.id===next.id).plan.resumes_run_id,source.id);
  assert(before.observations.every(row=>final.observations.some(candidate=>candidate.id===row.id)));
  assert.equal(final.investigations[0].tests.length,2);assert.equal(final.investigations[0].decision,'undecided');
  for(const token of [preview.token,freshReview.token])assert(!JSON.stringify(final).includes(token));
  stage='restart the page with durable expectations and no restored execution authority';await page.reload();await go(page,'investigations');
  await page.locator('#investigation-list [data-investigation="'+investigation.id+'"]').click();
  assert.equal(await page.locator('#investigation-interface').inputValue(),expected);
  await page.screenshot({path:path.join(output,'execution-context-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.screenshot({path:path.join(output,'execution-context-mobile.png'),fullPage:true});
  const redacted=await page.evaluate(async id=>api('export',{workspace:id}),workspace);
  assert.equal(redacted.investigations[0].execution_context,'[withheld]');assert(!JSON.stringify(redacted).includes(fixture));
  assert.equal(errors.length,0,errors.join('\n'));
  await fs.writeFile(path.join(output,'context-workflow-verification.json'),JSON.stringify({passed:true,synthetic:true,workspace_id:workspace,investigation_id:investigation.id,
    source_run:source.id,source_state:incomplete.state,new_run:next.id,interface:expected,
    checks:['saved actual host/interface','no start before current review','DNS-only review with zero target TCP connections','limit/URL edits invalidate review',
    'real interruption retains partial evidence','no automatic negative verdict','resume preparation has no request/query/session/authorization authority',
    'fresh review produces a new run linked to unchanged original','page reload preserves expected context','default export redacts context','390px layout'],
    page_errors:errors,limitations:['Owned loopback fixture only; no real HTB VPN/target supplied.','Process restart and token/auth loss are tested separately by test_execution_api.py.']},null,2));
  console.log('Execution context review, interrupted safe resume and retained evidence UI workflow passed.');
})().catch(error=>{console.error('Context workflow failed during '+stage+': '+error.stack);process.exitCode=1;})
  .finally(async()=>{for(const response of held.splice(0))response.end();if(browser)await browser.close();for(const socket of sockets)socket.destroy();if(target)await new Promise(resolve=>target.close(resolve));});
