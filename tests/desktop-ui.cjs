/* Actual Edge UI acceptance for the local app/optional companion boundary.
 * Remote result responses are explicitly stubbed only for stale-response UI
 * checks. Verified HTTPS, authentication, save custody and inferred handoff are
 * exercised independently by test_companion.py; no live remote server is used.
 */
'use strict';
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const go=require('./ui-navigation.cjs');
let stage='setup',browser;
(async()=>{
  const base=(process.env.ATLAS_UI_URL||'http://127.0.0.1:8797').replace(/\/$/,'');
  const output=process.env.ATLAS_UI_OUTPUT||path.join(__dirname,'../test-results/desktop');
  await fs.mkdir(output,{recursive:true});
  browser=await chromium.launch({channel:'msedge',headless:true});
  const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],external=[],operations=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{
    if(!request.url().startsWith(base+'/')&&!/^(data:|blob:)/.test(request.url()))external.push(request.url());
    if(/\/api\/(companion\/(connect|run|save)|updates\/check|web\/start|terminal\/start|vulnerability\/scan)$/.test(request.url()))operations.push(request.url());
  });
  const model=id=>page.evaluate(async id=>api('workspace?id='+encodeURIComponent(id)),id);
  async function create(name){
    await page.locator('#new-workspace').click();await page.locator('#new-name').fill(name);
    await page.locator('#new-scope').fill('Synthetic local desktop UI acceptance. No live targets or remote companion.');
    await page.locator('#new-form .primary').click();await page.locator('#new-dialog').waitFor({state:'hidden'});
    return page.locator('#workspace').inputValue();
  }
  async function openSettings(){
    await go(page,'tools');await page.locator('#tools-search').fill('companion');
    await page.getByRole('button',{name:'Open App & server',exact:true}).click();
    await page.locator('#appsettings').waitFor({state:'visible'});
  }
  await page.goto(base);await page.locator('#tools-search').waitFor({state:'attached'});
  await page.locator('#companion-status').filter({hasText:'Disconnected'}).waitFor({state:'attached'});
  assert.equal(operations.length,0,'Opening the application must not connect, update or start tools.');

  stage='find app and server controls';
  const first=await create('Synthetic desktop first '+Date.now());
  await openSettings();
  assert.match(await page.locator('#app-execution-position').innerText(),/machine.*VPN|host/i);
  assert.match(await page.locator('#app-update-status').innerText(),/No update check/);
  assert.equal(await page.locator('#companion-allow').isChecked(),false);
  assert.equal(await page.locator('#companion-save').isDisabled(),true);
  assert.equal(await page.locator('#companion-finding').isDisabled(),true);
  assert.equal(operations.length,0);

  stage='real rejection of insecure companion address and clearing password';
  await page.locator('#companion-origin').fill('http://192.0.2.50');
  await page.locator('#companion-password').fill('DESKTOP_UI_SYNTHETIC_ONLY');
  await page.locator('#companion-connect .primary').click();
  await page.locator('#message').filter({hasText:/HTTPS|https/}).waitFor();
  assert.equal(await page.locator('#companion-password').inputValue(),'');
  assert.match(await page.locator('#companion-status').innerText(),/Disconnected/);
  assert.equal(((await model(first)).web_runs?.length||0),0);

  stage='import exact synthetic fingerprint and deliberately prepare identities';
  await go(page,'import');await page.locator('#import-file').setInputFiles(path.join(__dirname,'../fixtures/vulnerability-nmap.xml'));
  await page.locator('#import-form .primary').click();await page.getByRole('button',{name:'Save this import',exact:true}).click();
  await page.getByRole('button',{name:'Save this import',exact:true}).waitFor({state:'detached'});
  await openSettings();
  const candidates=await page.evaluate(async id=>(await api('vulnerability/status?workspace='+id)).inventory_candidates,first);
  const candidate=candidates.find(row=>row.kind==='cpe');assert(candidate,'Fixture must provide a CPE candidate.');
  await page.locator('#companion-subject').selectOption(candidate.subject);
  await page.locator('#companion-candidates').click();
  await page.waitForFunction(()=>document.getElementById('companion-inventory').value.includes('cpe:'));
  const inventory=JSON.parse(await page.locator('#companion-inventory').inputValue());
  assert(inventory.every(row=>Object.keys(row).sort().join(',')==='cpe,kind'));
  assert.equal(await page.locator('#companion-allow').isChecked(),false);
  assert.equal(operations.filter(url=>url.endsWith('/companion/run')).length,0,'Preparing identities must not share or analyze them.');
  await page.locator('#companion-analyze .primary').click();
  await page.locator('#message').filter({hasText:/sharing|share|review|connect/i}).waitFor();
  assert.equal((await model(first)).findings.length,0);
  assert.equal(((await model(first)).web_runs?.length||0),0);

  stage='late analysis cannot populate a different workspace';
  const second=await create('Synthetic desktop second '+Date.now());
  await page.locator('#workspace').selectOption(first);await page.waitForFunction(id=>state?.id===id,first);
  await openSettings();
  await page.locator('#companion-subject').selectOption(candidate.subject);
  await page.locator('#companion-inventory').fill(JSON.stringify(inventory));await page.locator('#companion-allow').check();
  let release;const held=new Promise(resolve=>release=resolve);let requested;
  const sent=new Promise(resolve=>requested=resolve);
  await page.route('**/api/companion/run',async route=>{
    requested(route.request().postDataJSON());await held;
    await route.fulfill({json:{report_id:'synthetic-ui-stub-only',report:{summary:'SYNTHETIC_DELAYED_RESULT_NOT_EVIDENCE',matches:[]}}});
  });
  const click=page.locator('#companion-analyze .primary').click();const submitted=await sent;await click;
  assert.equal(submitted.workspace,first);assert.equal(submitted.allow_share,true);
  await page.locator('#workspace').selectOption(second);await page.waitForFunction(id=>state?.id===id,second);
  const responded=page.waitForResponse(response=>response.url().endsWith('/api/companion/run'));release();
  await (await responded).finished();await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(resolve)));
  assert.equal(await page.locator('#companion-inventory').inputValue(),'[]');
  assert.equal(await page.locator('#companion-allow').isChecked(),false);
  assert.equal(await page.locator('#companion-result').innerText(),'');
  assert.equal(await page.locator('#companion-save').isDisabled(),true);
  assert.equal(await page.locator('#companion-finding').isDisabled(),true);
  await page.unroute('**/api/companion/run');

  stage='inventory edits revoke a prepared report and consent';
  await page.locator('#workspace').selectOption(first);await page.waitForFunction(id=>state?.id===id,first);
  await page.locator('#companion-subject').selectOption(candidate.subject);
  await page.locator('#companion-inventory').fill(JSON.stringify(inventory));await page.locator('#companion-allow').check();
  await page.route('**/api/companion/run',route=>route.fulfill({json:{report_id:'synthetic-ui-stub-only',report:{summary:'SYNTHETIC_UI_DISPLAY_ONLY',matches:[]}}}));
  await page.locator('#companion-analyze .primary').click();
  await page.locator('#companion-result').filter({hasText:'SYNTHETIC_UI_DISPLAY_ONLY'}).waitFor();
  assert.equal(await page.locator('#companion-save').isEnabled(),true);
  await page.locator('#companion-inventory').fill('[]');
  assert.equal(await page.locator('#companion-allow').isChecked(),false);
  assert.equal(await page.locator('#companion-result').innerText(),'');
  assert.equal(await page.locator('#companion-save').isDisabled(),true);
  await page.unroute('**/api/companion/run');

  stage='explicit update failure and local evidence preserved';
  await page.route('**/api/updates/check',route=>route.fulfill({status:400,json:{error:'Synthetic update check unavailable; local work remains available.'}}));
  await page.locator('#app-update-check').click();await page.locator('#message').filter({hasText:'Synthetic update check unavailable'}).waitFor();
  await page.unroute('**/api/updates/check');
  const saved=await model(first);assert.equal(saved.imports.length,1);assert.equal(saved.findings.length,0);assert.equal((saved.web_runs?.length||0),0);
  assert.equal(operations.filter(url=>url.endsWith('/companion/save')).length,0);
  await page.screenshot({path:path.join(output,'desktop-app-server.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth),390);
  await page.screenshot({path:path.join(output,'desktop-app-server-mobile.png'),fullPage:true});
  const preferences=await page.evaluate(()=>JSON.stringify({...localStorage}));
  assert.doesNotMatch(preferences,/DESKTOP_UI_SYNTHETIC_ONLY|192\.0\.2\.50|SYNTHETIC_UI_DISPLAY_ONLY/);
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
  await fs.writeFile(path.join(output,'desktop-browser-verification.json'),JSON.stringify({passed:true,synthetic:true,
    checks:['no automatic connection/update/collection','tool directory app and server navigation','insecure HTTP address refused by actual backend','password control clears after attempted sign-in','synthetic CPE preparation shares no target/asset fields','sharing is deliberate','late results discarded after workspace change','inventory edits revoke report and consent','update failure preserves local assessment','desktop and mobile reflow','browser preferences exclude credentials and target data'],
    stubbed_only:['two companion run responses for UI stale-state checks','one update failure'],remote_tls_tested_here:false,
    retained_mock_reports:0,target_operations_started:0,page_errors:errors,external_ui_requests:external},null,2));
  await browser.close();console.log('Desktop companion navigation, disclosure, stale-response isolation and mobile workflow passed.');
})().catch(async error=>{console.error('Desktop UI failed at '+stage+': '+String(error.stack||error).slice(0,1800));if(browser)await browser.close();process.exit(1);});
