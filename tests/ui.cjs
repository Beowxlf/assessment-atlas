/* Real browser workflow tests for the local application, using synthetic files. */
const {chromium}=require(process.env.ATLAS_PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
const path=require('node:path');
const fs=require('node:fs/promises');
const root=path.resolve(__dirname,'..');
const output=process.env.ATLAS_UI_OUTPUT || path.join(root,'test-results');
(async()=>{
  await fs.mkdir(output,{recursive:true});
  const browser=await chromium.launch({channel:'msedge',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
  const page=await context.newPage();const errors=[],external=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{if(!r.url().startsWith('http://127.0.0.1:')&&!r.url().startsWith('blob:'))external.push(r.url());});
  const base=process.env.ATLAS_UI_URL || 'http://127.0.0.1:8765';
  const name='Browser synthetic '+Date.now();
  await page.goto(base);await page.locator('#version').filter({hasText:'Version'}).waitFor();
  await page.locator('#new-workspace').click();await page.locator('#new-name').fill(name);await page.locator('#new-scope').fill('Authorized synthetic browser workflow; no real targets.');await page.locator('#new-form button.primary').click();
  for(const filename of ['nmap.xml','device.json','scan.nessus','nuclei.jsonl','httpx.jsonl','manual.json']){
    await page.locator('nav [data-view="import"]').click();
    await page.locator('#import-file').setInputFiles(path.join(root,'fixtures',filename));await page.locator('#import-vantage').fill('Synthetic browser position');
    await page.locator('#import-form button.primary').click();await page.getByRole('button',{name:'Save this import',exact:true}).click();
    await page.locator('#message').filter({hasText:'Import saved'}).waitFor();
  }
  await page.locator('nav [data-view="map"]').click();assert((await page.locator('#graph g.node').count())>10);
  await page.screenshot({path:path.join(output,'map-desktop.png'),fullPage:true});
  await page.locator('#graph .edge-focus').first().focus();await page.keyboard.press('Enter');await page.locator('#detail-dialog').waitFor({state:'visible'});assert((await page.locator('#detail-body').innerText()).includes('sha256'));await page.locator('#close-detail').click();
  const options=await page.locator('#identity-left option').evaluateAll(els=>els.map(e=>({value:e.value,text:e.textContent})));
  const routers=options.filter(o=>o.text.startsWith('Synthetic router'));
  assert(routers.length>=2);await page.locator('#identity-left').selectOption(routers[0].value);await page.locator('#identity-right').selectOption(routers[routers.length-1].value);await page.locator('#identity-reason').fill('Synthetic identifiers and evidence reviewed; retain conflicting history.');await page.locator('#reconcile-form button').click();await page.locator('#message').filter({hasText:'Identities linked'}).waitFor();
  await page.getByRole('button',{name:'Undo link',exact:true}).click();await page.locator('#message').filter({hasText:'undone'}).waitFor();
  await page.locator('nav [data-view="activity"]').click();await page.locator('#record-title').fill('Check synthetic guest access');await page.locator('#record-details').fill('Unanswered question; no test has run.');await page.locator('#record-evidence').fill('Synthetic manual import reference');await page.locator('#record-form button.primary').click();await page.locator('#records-list').filter({hasText:'Check synthetic guest access'}).waitFor();
  await page.locator('nav [data-view="findings"]').click();assert.equal(await page.locator('#finding-list article').count(),2);await page.locator('#finding-list .review-form input').first().fill('Synthetic review: independently validated impact remains unknown.');await page.locator('#finding-list .review-form select').first().selectOption('needs retest');await page.locator('#finding-list .review-form button').first().click();await page.locator('#message').filter({hasText:'Review saved'}).waitFor();
  await page.reload();await page.locator('#version').filter({hasText:'Version'}).waitFor();await page.locator('#workspace-title').filter({hasText:name}).waitFor();
  await page.locator('nav [data-view="activity"]').click();assert((await page.locator('#records-list').innerText()).includes('Check synthetic guest access'));
  await page.locator('nav [data-view="import"]').click();await page.locator('#import-file').setInputFiles(path.join(root,'fixtures','nmap.xml'));await page.locator('#import-vantage').fill('Synthetic browser position');await page.locator('#import-form button.primary').click();await page.getByRole('button',{name:'Save this import',exact:true}).click();await page.locator('#message').filter({hasText:'Identical import already saved'}).waitFor();
  await page.locator('#import-file').setInputFiles({name:'hostile.xml',mimeType:'text/xml',buffer:Buffer.from('<!DOCTYPE nmaprun SYSTEM "https://example.test/x"><nmaprun><host/></nmaprun>')});await page.locator('#import-form button.primary').click();await page.locator('#message.error').waitFor();assert((await page.locator('#message').innerText()).includes('document types'));
  await page.locator('nav [data-view="report"]').click();await page.locator('#preview-export').click();await page.locator('#export-preview').filter({hasText:'withheld'}).waitFor();assert(!(await page.locator('#export-preview').innerText()).includes('portal.example.test'));
  for(const [selector,filename] of [['#download-json','results.json'],['#download-html','report.html'],['#download-svg','map.svg']]){const download=page.waitForEvent('download');await page.locator(selector).click();await (await download).saveAs(path.join(output,filename));}
  const results=JSON.parse(await fs.readFile(path.join(output,'results.json'),'utf8'));assert.equal(results.imports.length,6);assert(results.observations.every(o=>o.import_id));assert(results.export.redactions.length>0);
  assert((await fs.readFile(path.join(output,'report.html'),'utf8')).includes('Sources and provenance'));
  assert((await fs.readFile(path.join(output,'map.svg'),'utf8')).includes('<metadata>'));
  await page.locator('#export-identifiers').check();await page.locator('#preview-export').click();await page.locator('#export-preview').filter({hasText:'portal.example.test'}).waitFor();
  await page.locator('nav [data-view="map"]').click();await page.locator('#edge-filter').selectOption('local neighbor');assert.equal(await page.locator('#graph .edge-focus').count(),1);
  await page.locator('nav [data-view="report"]').click();const filteredDownload=page.waitForEvent('download');await page.locator('#download-json').click();await (await filteredDownload).saveAs(path.join(output,'filtered-results.json'));const filtered=JSON.parse(await fs.readFile(path.join(output,'filtered-results.json'),'utf8'));assert.equal(filtered.observations.length,1);assert.equal(filtered.export.selection.kind,'local neighbor');await page.locator('nav [data-view="map"]').click();
  await page.locator('#source-filter').selectOption('');await page.locator('#edge-filter').selectOption('');
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(output,'map-mobile.png'),fullPage:true});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  await page.locator('nav [data-view="import"]').click();await page.screenshot({path:path.join(output,'import-mobile.png'),fullPage:true});
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  await page.setViewportSize({width:1440,height:1000});await page.locator('nav [data-view="overview"]').click();await page.screenshot({path:path.join(output,'overview-desktop.png'),fullPage:true});
  await page.locator('nav [data-view="report"]').click();await page.locator('#delete-confirmation').fill(name);await page.locator('#delete-workspace').click();await page.locator('#message').filter({hasText:'Workspace deleted'}).waitFor();
  assert.equal(errors.length,0,errors.join('\n'));assert.equal(external.length,0,external.join('\n'));
  await fs.writeFile(path.join(output,'browser-verification.json'),JSON.stringify({passed:true,browser:'Microsoft Edge headless',desktop:[1440,1000],mobile:[390,844],synthetic:true,external_requests:external,page_errors:errors,checks:['six direct file imports','evidence keyboard activation','identity link and undo','assessment activity and finding review','reload persistence','deduplication','hostile XML rejection','redacted and identifier export previews','JSON/HTML/SVG downloads','map filtering','narrow viewport document width','workspace deletion']},null,2));
  console.log('Browser workflow passed: direct imports, evidence, reconciliation, activity, persistence, hostile input, exports, responsive layout, deletion.');
  await browser.close();
})().catch(err=>{console.error(err);process.exit(1);});
