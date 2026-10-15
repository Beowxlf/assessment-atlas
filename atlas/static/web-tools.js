'use strict';
let webWorkspace='',webCaptures=[],webPolling=false,webBrowsers=[],webSockets=[];
let webPollDone=Promise.resolve();
let webInvestigationContext=null;
let webExecutionStatus=null,webExecutionLoading=null,webContextPreview=null,webContextGeneration=0,webResumesRunId='';
function webInvalidateContext(reason='Configuration changed. Preview execution and routes again.'){
  webContextGeneration++;webContextPreview=null;
  if($('web-context-status'))$('web-context-status').textContent=reason;
}
function webResetInvestigationContext(){webInvestigationContext=null;webResumesRunId='';$('web-investigation-context')?.remove();if($('web-execution-enabled')){$('web-execution-enabled').disabled=false;$('web-execution-enabled').checked=false;$('web-interface').disabled=true;}webInvalidateContext('No current route preview. A saved session or previous run does not prove current connectivity.');}
window.atlasResetInvestigationTest=webResetInvestigationContext;
async function webLoadExecutionStatus(){
  needsWorkspace();const workspace=state.id;
  if(webExecutionStatus?.workspace===workspace)return webExecutionStatus.data;
  if(webExecutionLoading?.workspace===workspace)return webExecutionLoading.promise;
  const pending={workspace,promise:api('execution/status?workspace='+encodeURIComponent(workspace))};webExecutionLoading=pending;
  try{const result=await pending.promise;if(state?.id===workspace)webExecutionStatus={workspace,data:result};return result;}finally{if(webExecutionLoading===pending)webExecutionLoading=null;}
}
window.atlasExecutionStatus=webLoadExecutionStatus;
function webInterfaceOptions(select,status,selected){
  select.replaceChildren();select.append(new Option('System route · no VPN proof','system'));
  const names=new Set((status.interfaces||[]).map(row=>typeof row==='string'?row:row.name));
  if(status.default_interface)names.add(status.default_interface);if(selected)names.add(selected);
  for(const name of names)if(name&&name!=='system'){const row=(status.interfaces||[]).find(row=>row.name===name);select.append(new Option(name+(row?.up===false?' · currently down':row?'':' · not currently present'),name));}
  for(const option of select.options)option.defaultSelected=option.value===(status.default_interface||'system');
  select.value=selected||status.default_interface||'system';
}
window.atlasExecutionInterfaceOptions=webInterfaceOptions;
async function webExecutionView(){
  if(!$('web-execution-host')||!state)return;const workspace=state.id;
  try{const status=await webLoadExecutionStatus();if(state?.id!==workspace)return;
    const bound=webInvestigationContext?.workspace===workspace?webInvestigationContext.execution_context:null;
    const selected=bound?.interface||($('web-interface').dataset.initializedWorkspace===workspace?$('web-interface').value:status.default_interface);
    webInterfaceOptions($('web-interface'),status,selected);$('web-interface').dataset.initializedWorkspace=workspace;
    $('web-execution-host').value=status.host.name+' · '+status.host.platform+' · execution server';
    $('web-execution-host').dataset.hostId=bound?.host_id||status.host.id;
    $('web-execution-note').textContent=bound?.host_id&&bound.host_id!==status.host.id?'Blocked: the saved execution host differs from this server. Change the investigation context and prepare again.':'Requests run on this Atlas server, not the computer viewing the page. A route through an interface does not prove HTB authorization or VPN health.';
    const boundInvestigation=!!webInvestigationContext;$('web-execution-enabled').disabled=boundInvestigation;if(boundInvestigation)$('web-execution-enabled').checked=true;$('web-interface').disabled=boundInvestigation||!$('web-execution-enabled').checked;
  }catch(error){if(state?.id===workspace)$('web-execution-note').textContent='Execution host unavailable: '+error.message;}
}
function webOperationConfig(kind){
  if(webInvestigationContext&&['proxy','browser','websocket'].includes(kind))throw new Error('This tool cannot link an investigation run yet. Keep the saved question and use a supported test, or deliberately clear its workbench link for standalone work.');
  let config;
  if(kind==='scanner')config=webScanConfig();
  else if(kind==='request')config=webRequestConfig();
  else if(kind==='payload')config={...webRequestConfig(),parameter:$('web-parameter').value,parameter_location:$('web-parameter-location').value,payloads:webLines('web-payloads')};
  else if(kind==='matrix')config={...webRequestConfig(),session_id:$('web-session').value,active_audit:$('web-active-audit').checked,checks:['passive'],positions:webJSON('web-positions'),attack_mode:$('web-attack-mode').value,processor:$('web-processor').value};
  else if(kind==='websocket')config={...webConfig(),session_id:$('web-session').value,ws_url:$('web-ws-url').value};
  else if(['proxy','browser'].includes(kind))config=webConfig();
  else config={...webConfig(),paths:webLines('web-paths'),crawl:$('web-follow').checked};
  return {...config,...(config.execution_context?{execution_kind:kind}:{})};
}
function webCurrentOperation(){const pane=[...document.querySelectorAll('.web-pane')].find(pane=>!pane.hidden)?.id;return {'web-pane-request':'request','web-pane-payload':'payload','web-pane-scanner':'scanner','web-pane-advanced':'matrix','web-pane-proxy':'proxy','web-pane-browser':'browser','web-pane-protocols':'websocket'}[pane]||'crawl';}
async function webConfigDigest(config){const copy={...config};delete copy.context_token;const bytes=new TextEncoder().encode(JSON.stringify(copy));return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(value=>value.toString(16).padStart(2,'0')).join('');}
async function webReviewed(config){
  if(!config.execution_context)return config;
  const preview=webContextPreview,generation=webContextGeneration,digest=await webConfigDigest(config);
  if(!preview||preview!==webContextPreview||preview.expiresAt<=Date.now()||preview.generation!==webContextGeneration||generation!==webContextGeneration||preview.digest!==digest){
    webInvalidateContext('Execution readiness changed or expired. Preview this operation again before launching.');throw new Error('Preview execution and routes for the current configuration before launching this test.');
  }
  const reviewed={...config,context_token:preview.token};webInvalidateContext('Reviewed operation submitted. This preview is single-use; preview again before another launch.');return reviewed;
}
async function webPreviewContext(){
  needsWorkspace();const workspace=state.id,startingGeneration=webContextGeneration;
  if(!$('web-authorized').checked)throw new Error('Review the exact target and authorize its scope before previewing routes.');
  $('web-execution-enabled').checked=true;await webExecutionView();
  if(state?.id!==workspace||startingGeneration!==webContextGeneration)return;
  const config=webOperationConfig(webCurrentOperation()),generation=webContextGeneration,digest=await webConfigDigest(config);
  if(state?.id!==workspace||generation!==webContextGeneration)return;
  $('web-context-status').textContent='Checking execution host, target resolution and routes; no target connection is opened…';
  let result;try{result=await api('execution/preview',{workspace,...config});}catch(error){if(state?.id===workspace&&generation===webContextGeneration)webInvalidateContext('Readiness unavailable: '+error.message);throw error;}
  if(state?.id!==workspace||generation!==webContextGeneration)return;
  webContextPreview={token:result.token,expiresAt:Date.now()+result.expires_in*1000,digest,generation};
  const routes=(result.routes||[]).map(route=>typeof route==='string'?route:[route.target||route.address||route.destination,route.interface||route.dev].filter(Boolean).join(' via ')).join('; ');
  $('web-context-status').textContent='Ready · '+result.host.name+' · expected '+result.interface+(routes?' · '+routes:'')+' · checked '+result.checked_at+'. Rechecked at execution; this is not proof of target reachability or VPN authorization.';
}
function webAdvanceInvestigation(result){
  if(webInvestigationContext?.workspace===state?.id && (result.investigation_id||result.plan?.investigation_id)===webInvestigationContext.investigation_id && Number.isInteger(result.investigation_revision)){webInvestigationContext.revision=result.investigation_revision;webInvalidateContext('Run linked. Preview the current configuration again before starting another run.');}
}
window.atlasPrepareInvestigationTest=async context=>{
  needsWorkspace();
  if(state.id!==context.workspace)throw new Error('Return to the investigation workspace before preparing a test.');
  const workspace=state.id;
  const node=state.nodes.find(n=>n.members.includes(context.subject));
  const entry=node&&operatorURLs(node)[0];
  await operatorPrepareWeb(entry||null);
  if(state?.id!==workspace)return;
  webInvestigationContext={workspace,investigation_id:context.investigation_id,revision:context.revision,execution_context:context.execution_context,access_role:context.access_role||'',access_reference:context.access_reference||''};
  webResumesRunId=context.resume_preparation?.resumes_run_id||'';
  if(context.resume_preparation){const preparation=context.resume_preparation,saved=preparation.config||{};
    for(const [key,id] of [['url','web-url'],['path_prefix','web-prefix'],['max_requests','web-limit'],['max_seconds','web-seconds'],['delay_ms','web-delay'],['max_depth','web-depth']])if(saved[key]!==undefined)$(id).value=String(saved[key]);
    $('web-origins').value=(saved.extra_origins||[]).join('\n');$('web-exclude').value=(saved.exclude_paths||[]).join('\n');$('web-request-url').value=saved.url||'';
  }
  const resumedTab={request:'request',crawl:'crawl',scanner:'scanner',payload:'payload',matrix:'advanced'}[context.resume_preparation?.kind];
  document.querySelector('[data-web-tab="'+(resumedTab||(context.access_mode==='authenticated'?'scanner':'request'))+'"]').click();
  if(context.access_mode==='authenticated'){$('web-auth-settings').hidden=false;$('web-auth-toggle').setAttribute('aria-expanded','true');}
  const banner=el('div','','operator-context');banner.id='web-investigation-context';
  banner.append(el('span',(webResumesRunId?'Prepare a new independent run from '+webResumesRunId+'. Original results remain unchanged. ':'Test prepared for this investigation. ')+(context.access_role?'Role: '+context.access_role+'. ':'')+'Review host/interface, scope and limits, then preview routes'+(context.access_mode==='authenticated'?'; re-establish and select a transient authentication session.':'.')),
    button('Return to investigation',()=>show('investigations')),button('Clear investigation link',webResetInvestigationContext));
  $('web').insertBefore(banner,$('web').firstChild);
  if(context.resume_preparation?.limitations?.length)banner.append(el('p',context.resume_preparation.limitations.join(' '),'muted'));
  if(webResumesRunId)banner.append(el('p','The prepared scope keeps the original main path boundary and exclusions. Its sanitized URL withholds query values. Re-enter request inputs and authentication as needed, then review the scope and preview a new bounded run.','muted'));
  $('web-authorized').checked=false;
  await webExecutionView();webInvalidateContext('Test prepared. Review scope, authentication and execution context, then preview routes.');
  message('Investigation test prepared. Review the target, limits and authorization before starting'+(context.access_mode==='authenticated'?'; saved access references do not restore authentication.':'.'));
};
function webLines(id){return $(id).value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);}
function webConfig(){
  needsWorkspace();
  const execution=$('web-execution-enabled')?.checked?{execution_context:webInvestigationContext?.execution_context||{host_id:$('web-execution-host').dataset.hostId,interface:$('web-interface').value}}:{};
  return {http_version:$('web-http-version').value,url:$('web-url').value,path_prefix:$('web-prefix').value,extra_origins:webLines('web-origins'),exclude_paths:webLines('web-exclude'),ca_pem:$('web-ca').value,authorized:$('web-authorized').checked,vantage:$('web-vantage').value,namespace:$('web-namespace').value,retain_body:$('web-retain').checked,max_requests:Number($('web-limit').value),max_seconds:Number($('web-seconds').value),delay_ms:Number($('web-delay').value),max_depth:Number($('web-depth').value),proxy_port:Number($('web-proxy-port').value),...execution,...(webContextPreview?{context_token:webContextPreview.token}:{}),...(webResumesRunId?{resumes_run_id:webResumesRunId}:{}),...(webInvestigationContext?.workspace===state.id?{investigation_id:webInvestigationContext.investigation_id,investigation_revision:webInvestigationContext.revision,access_role:webInvestigationContext.access_role,access_reference:webInvestigationContext.access_reference}:{})};
}
function webRequestConfig(){return {...webConfig(),request_url:$('web-request-url').value||$('web-url').value,method:$('web-method').value,headers:$('web-headers').value,body:$('web-body').value};}
function webJSON(id){return $(id).value.trim()?JSON.parse($(id).value):[];}
function webAuthConfig(){return {...webConfig(),session_label:$('web-session-label').value,auth:{origins:webLines('web-auth-origins').length?webLines('web-auth-origins'):[new URL($('web-url').value).origin],check_url:$('web-auth-check').value,success_text:$('web-auth-marker').value,headers:$('web-auth-headers').value,steps:webJSON('web-auth-steps')}};}
function webScanConfig(){return {...webConfig(),session_id:$('web-session').value,checks:[...document.querySelectorAll('#web-checks input:checked, #web-more-checks input:checked')].map(n=>n.value),audit_crawl:$('web-audit-crawl').checked,active_audit:$('web-active-audit').checked,protected_marker:$('web-protected-marker').value,exclude_parameters:webLines('web-exclude-parameters'),audit_requests:webJSON('web-audit-requests'),custom_checks:webJSON('web-custom-checks'),canary_path:$('web-canary-path').value,canary_marker:$('web-canary-marker').value,canary_url:$('web-canary-url').value,oob_id:$('web-oob-select').value};}
function webClearAuth(){for(const id of ['web-auth-headers','web-auth-steps','web-login-user','web-login-password'])$(id).value='';webInvalidateContext('Authentication inputs changed. Preview the final operation after establishing its transient session.');}
async function webRefresh(fresh=false){
  if(!$('web-runs'))return;
  if(webWorkspace!==(state?.id||'')){
    webResetInvestigationContext();
    webWorkspace=state?.id||'';webCaptures=[];if(window.atlasHosted){$('web-vantage').defaultValue='Atlas Linux server';}$('web-scope').reset();$('web-headers').value='';$('web-body').value='';$('web-url').value='';$('web-request-url').value='';clear('web-compare-left');clear('web-compare-right');clear('web-request-result');clear('web-comparison');clear('web-proxy-credentials');clear('web-intercepts');
    webClearAuth();for(const id of ['web-auth-check','web-auth-marker','web-auth-origins','web-protected-marker','web-audit-requests','web-custom-checks','web-schema','web-positions','web-utility-input','web-exclude-parameters'])$(id).value='';for(const id of ['web-session-result','web-schema-result','web-utility-result'])clear(id);clear('web-session').append(new Option('Unauthenticated',''));webBrowsers=[];webSockets=[];clear('web-ws-messages');clear('web-ws-select');clear('web-ws-evidence');clear('web-oob-token');clear('web-oob-events');$('web-oob-remote').checked=false;
    $('web-auth-settings').hidden=true;$('web-auth-toggle').setAttribute('aria-expanded','false');
    for(const id of ['web-oob-advertise','web-ws-url','web-ws-message','web-ws-finding-title','web-ws-detail','web-canary-path','web-canary-marker','web-canary-url','web-login-url','web-login-preflight','web-login-csrf','web-login-bearer'])$(id).value='';$('web-session-label').value='Assessment session';$('web-active-audit').checked=false;document.querySelectorAll('#web-checks input, #web-more-checks input').forEach(input=>input.checked=input.value==='passive');
    webExecutionView();
  }
  if(!state){clear('web-runs').append(el('p','Create or select a workspace before configuring live tools.','muted'));return;}
  if(webPolling){if(!fresh)return;await webPollDone;return webRefresh(true);}
  webPolling=true;let finishPoll;webPollDone=new Promise(resolve=>finishPoll=resolve);
  try{
    const id=state.id;const result=await api('web/status?workspace='+encodeURIComponent(id));if(state?.id!==id)return;
    $('web-protocol-availability').textContent='Optional engines: '+Object.entries(result.protocols||{}).map(([name,ready])=>name+' '+(ready?'available':'requires protocol setup')).join(' · ');webBrowsers=result.browsers;webSockets=result.sockets||[];const chosenWS=$('web-ws-select').value;clear('web-ws-select');for(const s of webSockets)$('web-ws-select').append(new Option(s.id.slice(0,8)+' · '+s.state,s.id));if(webSockets.some(s=>s.id===chosenWS))$('web-ws-select').value=chosenWS;const receiverID=$('web-oob-select').value;clear('web-oob-select').append(new Option('Choose active receiver',''));for(const r of result.receivers||[])if(r.state==='running')$('web-oob-select').append(new Option(r.callback_origin,r.id));if((result.receivers||[]).some(r=>r.id===receiverID&&r.state==='running'))$('web-oob-select').value=receiverID;clear('web-oob-events');for(const r of result.receivers||[])$('web-oob-events').append(el('pre',JSON.stringify(r,null,2)));webMessageView();const selectedSession=$('web-session').value;clear('web-session').append(new Option('Unauthenticated',''));for(const session of result.sessions||[])$('web-session').append(new Option(session.label+' · '+Math.ceil(session.remaining_seconds/60)+' minutes',session.id));if((result.sessions||[]).some(s=>s.id===selectedSession))$('web-session').value=selectedSession;
    if(selectedSession&&$('web-session').value!==selectedSession)webInvalidateContext('The selected authentication session expired or disappeared. Establish a fresh session and preview this operation again.');
    clear('web-runs');
    for(const r of [...result.runs].reverse()){
      const row=el('div','','list-item');row.append(badge(r.state),el('strong',r.kind+' · '+(r.requests===null?'request count unavailable':r.requests+' requests')),el('p',r.reason||'Bounded collection in progress','subline'),button('Inspect plan and evidence references',()=>details('Web run '+r.kind,[r])));
      if(r.audited_endpoints!==undefined)row.append(el('p',r.audited_endpoints+' endpoints audited · '+(r.findings||0)+' findings saved · '+(r.session_refreshes||0)+' session refreshes','subline'));
      if(['running','queued'].includes(r.state)&&['crawl','payload','scanner','matrix'].includes(r.kind))row.append(button('Stop run',async()=>{await api('web/stop',{workspace:id,id:r.id});message('Stop requested. An in-flight request may finish; completed evidence remains saved.');}));
      $('web-runs').append(row);
    }
    if(!result.runs.length)$('web-runs').append(el('p','No native collection runs yet.','muted'));
    clear('web-proxy-status');const pending=new Set();
    for(const p of result.proxies){
      const row=el('div','','list-item');row.append(badge(p.state),el('strong','127.0.0.1:'+p.port+' · '+p.requests+' requests'));
      if(p.state==='running')row.append(button(p.intercept?'Turn interception off':'Intercept live requests',async()=>{await api('web/proxy/intercept',{workspace:id,id:p.id,enabled:!p.intercept});await webRefresh(true);}),button('Stop proxy / browser',async()=>{await api('web/proxy/stop',{workspace:id,id:p.id});clear('web-proxy-credentials');await webRefresh(true);}));
      if(p.state==='running')row.append(button(p.websocket_intercept?'Turn WebSocket interception off':'Intercept WebSocket messages',async()=>{await api('web/proxy/intercept-websocket',{workspace:id,id:p.id,enabled:!p.websocket_intercept});await webRefresh(true);}));
      if(p.state==='running')row.append(button(p.intercept_response?'Turn response interception off':'Intercept text responses',async()=>{await api('web/proxy/intercept-response',{workspace:id,id:p.id,enabled:!p.intercept_response});await webRefresh(true);}));
      $('web-proxy-status').append(row);
      for(const item of p.pending){
        pending.add(item.id);if(document.getElementById('intercept-'+item.id))continue;
        const card=el('article','','card');card.id='intercept-'+item.id;card.append(el('h3',item.method+' '+item.url),el('p','Transient request editor. No credentials or original message are saved by this editor.','muted'));
        if(item.phase==='websocket'){
          card.querySelector('p').textContent='Original application message is saved. Edit/forward or drop this message; binary messages use Base64.';const body=el('textarea');body.value=item.body;const binary=el('input');binary.type='checkbox';binary.checked=item.binary;const label=el('label','Binary / Base64');label.append(binary);card.append(body,label,button('Forward edited WebSocket message',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'forward',changes:{body:body.value,binary:binary.checked}});card.remove();}),button('Drop WebSocket message',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'drop'});card.remove();}));$('web-intercepts').append(card);continue;
        }
        if(item.phase==='response'){
          card.querySelector('p').textContent='Upstream evidence is already saved. This edited downstream response will be labeled as an operator modification.';const status=el('input');status.type='number';status.min='200';status.max='599';status.value=item.status;const headers=el('textarea');headers.value=item.headers.map(h=>h.name+': '+h.value).join('\n');const body=el('textarea');body.value=item.body;
          for(const [name,input] of [['Response status',status],['Response headers',headers],['Response body',body]]){const label=el('label',name);label.append(input);card.append(label);}
          card.append(button('Forward edited response',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'forward',changes:{status:Number(status.value),headers:headers.value,body:body.value}});card.remove();}),button('Drop response',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'drop'});card.remove();}));$('web-intercepts').append(card);continue;
        }
        const method=el('select');for(const name of ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])method.append(new Option(name,name));method.value=item.method;
        const headers=el('textarea');headers.value=item.headers.map(h=>h.name+': '+h.value).join('\n');const body=el('textarea');body.value=item.body;
        for(const [name,input] of [['Method',method],['Headers',headers],['Body',body]]){const label=el('label',name);label.append(input);card.append(label);}
        card.append(button('Forward edited request',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'forward',changes:{method:method.value,headers:headers.value,body:body.value}});card.remove();message('Request forwarded within scope.');}),button('Drop request',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'drop'});card.remove();message('Request dropped.');}));
        $('web-intercepts').append(card);
      }
    }
    for(const card of $('web-intercepts').children)if(!pending.has(card.id.replace('intercept-','')))card.remove();
    for(const browser of result.browsers)if(browser.error)$('web-proxy-status').append(el('p',browser.error,'muted'));
    if(['web','findings','map','discovery'].includes(currentView)&&!document.activeElement?.closest('.review-form')){
      const fresh=await api('workspace?id='+encodeURIComponent(id));if(state?.id===id&&(fresh.observations.length!==state.observations.length||JSON.stringify(fresh.web_runs)!==JSON.stringify(state.web_runs))){state=fresh;render();}
    }
  }finally{webPolling=false;finishPoll();}
}
function webMessageView(){
  clear('web-ws-messages');const selected=$('web-ws-evidence').value;clear('web-ws-evidence');const session=webSockets.find(s=>s.id===$('web-ws-select').value);
  for(const row of session?.messages||[]){$('web-ws-evidence').append(new Option(row.direction+' · '+row.id.slice(0,8),row.id));const card=el('article','','card');card.append(el('strong',row.direction+' · '+row.opcode+' · '+row.bytes+' bytes'),el('pre',row.body),button('Edit / replay this message',()=>{$('web-ws-message').value=row.body;$('web-ws-binary').checked=row.opcode==='binary';}));$('web-ws-messages').append(card);}if((session?.messages||[]).some(m=>m.id===selected))$('web-ws-evidence').value=selected;
}
window.atlasWebRefresh=()=>run(webRefresh);
run(async()=>{
  const response=await fetch('/web-tools.html');if(!response.ok)throw new Error('Web tools could not load.');
  const wrapper=el('div');wrapper.innerHTML=await response.text();document.querySelector('main').append(wrapper.firstElementChild);
  const nav=el('button','Web workbench');nav.dataset.view='web';nav.addEventListener('click',()=>{show('web');run(webRefresh);});document.querySelector('nav').append(nav);
  $('web-auth-toggle').addEventListener('click',()=>{const panel=$('web-auth-settings');panel.hidden=!panel.hidden;$('web-auth-toggle').setAttribute('aria-expanded',String(!panel.hidden));});
  const foot=document.querySelector('.sidebar-foot');for(const node of [...foot.childNodes])if(node!==$('version'))node.remove();foot.prepend(document.createTextNode('Imports stay local. Live tools use your explicit scope.'));
  document.querySelectorAll('[data-web-tab]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.web-pane').forEach(p=>p.hidden=p.id!=='web-pane-'+b.dataset.webTab);document.querySelectorAll('[data-web-tab]').forEach(n=>n.classList.toggle('selected',n===b));webInvalidateContext('Operation changed. Preview its execution and routes before launching.');}));
  $('web-context-preview').addEventListener('click',()=>run(webPreviewContext,$('web-context-preview')));
  $('web').addEventListener('input',event=>{if(event.target.id==='web-execution-host')return;webInvalidateContext('Configuration changed. Review and preview this operation again.');if(['web-url','web-prefix','web-origins','web-exclude','web-ca'].includes(event.target.id))$('web-authorized').checked=false;});
  $('web').addEventListener('change',event=>{webInvalidateContext('Target, access or execution context changed. Preview this operation again.');if(event.target.id==='web-execution-enabled')$('web-interface').disabled=!!webInvestigationContext||!$('web-execution-enabled').checked;if(['web-interface','web-execution-enabled'].includes(event.target.id)&&!webInvestigationContext)$('web-authorized').checked=false;});
  setInterval(()=>{if(webContextPreview&&webContextPreview.expiresAt<=Date.now())webInvalidateContext('Route preview expired. Preview current readiness before launching.');},1000);
  $('web-crawl').addEventListener('submit',e=>{e.preventDefault();run(async()=>{const config=await webReviewed(webOperationConfig('crawl'));const result=await api('web/start',{workspace:state?.id,kind:'crawl',config});webAdvanceInvestigation(result);message('Bounded enumeration started. Partial results are saved as requests complete.');await webRefresh(true);});});
  $('web-common-paths').addEventListener('click',()=>$('web-paths').value='/robots.txt\n/sitemap.xml\n/favicon.ico\n/api\n/docs');
  $('web-request').addEventListener('submit',e=>{e.preventDefault();run(async()=>{const config=await webReviewed(webOperationConfig('request'));const result=await api('web/request',{workspace:state?.id,config});webAdvanceInvestigation(result);webCaptures.push({id:result.capture_id,label:result.event.request.method+' '+result.event.url+' · '+(result.event.response?.status||'failed')});for(const select of ['web-compare-left','web-compare-right']){clear(select);for(const capture of webCaptures)$(select).append(new Option(capture.label,capture.id));}$('web-compare-right').value=result.capture_id;clear('web-request-result').append(el('h3','Captured response'),el('pre',JSON.stringify(result.event.response||{error:result.event.error},null,2)));message('Bounded response inspected; normalized scoped evidence saved.');await webRefresh(true);});});
  $('web-compare').addEventListener('click',()=>run(async()=>{const result=await api('web/compare',{workspace:state?.id,left:$('web-compare-left').value,right:$('web-compare-right').value});$('web-comparison').textContent=(result.identical?'Responses are identical.':result.diff)+'\n'+result.limit;}));
  $('web-payload').addEventListener('submit',e=>{e.preventDefault();run(async()=>{const config=await webReviewed(webOperationConfig('payload'));const result=await api('web/start',{workspace:state?.id,kind:'payload',config});webAdvanceInvestigation(result);message('Selected-parameter baseline and bounded tests started.');await webRefresh(true);});});
  $('web-scanner-start').addEventListener('click',()=>run(async()=>{const config=await webReviewed(webOperationConfig('scanner'));const result=await api('web/start',{workspace:state?.id,kind:'scanner',config});webAdvanceInvestigation(result);message('Crawl and audit started. Findings feed this assessment directly; review and validation remain explicit.');await webRefresh(true);},$('web-scanner-start')));
  async function keepSession(browser){const config=webAuthConfig();const active=webBrowsers.filter(b=>b.state==='running');if(browser&&active.length!==1)throw new Error('Open one isolated assessment browser and finish signing in first.');const result=await api(browser?'web/browser/session':'web/session/save',{workspace:state?.id,id:browser?active[0].id:undefined,config});webClearAuth();await webRefresh(true);$('web-session').value=result.id;clear('web-session-result').append(el('p','Session kept transiently and selected. It is validated against the protected marker when a scan starts.'));}
  $('web-login-build').addEventListener('click',()=>run(async()=>{
    const login=$('web-login-url').value,username=$('web-login-user').value,password=$('web-login-password').value,userField=$('web-login-user-field').value,passwordField=$('web-login-password-field').value;
    if(!login||!username||!password||!userField||!passwordField||userField===passwordField)throw new Error('Supply a login URL, credentials and two distinct field names.');
    const steps=[],body={[userField]:username,[passwordField]:password},csrf=$('web-login-csrf').value,preflight=$('web-login-preflight').value;
    if(csrf){if(!preflight)throw new Error('Supply the pre-login page URL for the hidden token.');steps.push({url:preflight,extract:{csrf:{from:'hidden',name:csrf}}});body[csrf]='{{csrf}}';}
    const form=$('web-login-format').value==='form';const step={url:login,method:'POST',headers:[{name:'Content-Type',value:form?'application/x-www-form-urlencoded':'application/json'}],body:form?new URLSearchParams(body).toString():JSON.stringify(body)};
    const bearer=$('web-login-bearer').value;if(bearer){step.extract={bearer:{from:'json',name:bearer}};$('web-auth-headers').value='Authorization: Bearer {{bearer}}';}steps.push(step);
    $('web-auth-steps').value=JSON.stringify(steps,null,2);$('web-auth-origins').value=[...new Set([new URL($('web-url').value).origin,new URL(login).origin,...(preflight?[new URL(preflight).origin]:[])])].join('\n');clear('web-session-result').append(el('p','Login sequence prepared locally. Keep the transient session to select it for scanning.'));
  }));
  $('web-session-save').addEventListener('click',()=>run(()=>keepSession(false),$('web-session-save')));
  $('web-session-browser').addEventListener('click',()=>run(()=>keepSession(true),$('web-session-browser')));
  $('web-session-forget').addEventListener('click',()=>run(async()=>{if(!$('web-session').value)throw new Error('Select a session to discard.');await api('web/session/forget',{workspace:state?.id,id:$('web-session').value});webClearAuth();await webRefresh(true);clear('web-session-result').append(el('p','Selected session discarded. Running scans keep their own copy until they stop.'));}));
  $('web-findings-open').addEventListener('click',()=>run(async()=>{await load(state.id);show('findings');}));
  $('web-matrix-start').addEventListener('click',()=>run(async()=>{const config=await webReviewed(webOperationConfig('matrix'));const result=await api('web/start',{workspace:state?.id,kind:'matrix',config});webAdvanceInvestigation(result);message('Baseline and bounded multi-position tests started.');await webRefresh(true);}));
  $('web-utility-run').addEventListener('click',()=>run(async()=>{needsWorkspace();const operation=$('web-utility-operation').value;const result=await api('web/utility',{workspace:state.id,operation,text:$('web-utility-input').value,samples:operation==='tokens'?webLines('web-utility-input'):undefined});$('web-utility-result').textContent=result.result??JSON.stringify(result,null,2);}));
  $('web-schema-load').addEventListener('click',()=>run(async()=>{const result=await api('web/schema',{workspace:state?.id,config:webConfig(),schema:JSON.parse($('web-schema').value)});$('web-schema-result').textContent=JSON.stringify(result,null,2);$('web-audit-requests').value=JSON.stringify(result.audit_requests,null,2);message('API requests previewed. Review them before starting an audit.');}));
  $('web-proxy-start').addEventListener('click',()=>run(async()=>{const config=await webReviewed(webOperationConfig('proxy'));const result=await api('web/proxy/start',{workspace:state?.id,config});webInvalidateContext('Proxy started. Its reviewed route remains bound while it runs; a new operation needs a fresh preview.');clear('web-proxy-credentials').append(el('p','Use only a separate test browser. Proxy credentials are transient and are not exported.'),el('pre','Proxy: http://127.0.0.1:'+result.port+'\nUsername: '+result.username+'\nPassword: '+result.password+'\nPublic CA SHA-256: '+result.CA_sha256),button('Download this public CA',async()=>{const response=await fetch('/api/web/ca?workspace='+encodeURIComponent(state.id)+'&id='+result.id);if(!response.ok)throw new Error('CA download failed');download(await response.text(),'atlas-isolated-proxy-ca.pem','application/x-pem-file');}));message('Scoped loopback proxy started. Existing browser/Burp trust and proxy settings are untouched.');await webRefresh(true);},$('web-proxy-start')));
  $('web-browser-start').addEventListener('click',()=>run(async()=>{if(window.atlasHosted){if(webInvestigationContext||$('web-execution-enabled').checked)throw new Error('The embedded browser handoff cannot carry this reviewed execution context. Keep the investigation saved; use its scanner/request controls, or explicitly clear the workbench link and use the separate embedded browser workflow.');const url=$('web-url').value,ca=$('web-ca').value;await operatorOpen({view:'console',consoleTab:'browser'});$('embedded-url').value=url;$('embedded-ca').value=ca;$('embedded-authorized').checked=false;message('Browser scope prepared. Authorize the embedded browser to sign in and interact here.');return;}const config=await webReviewed(webOperationConfig('browser'));await api('web/browser/start',{workspace:state?.id,config});webInvalidateContext('Browser started. A new operation needs a fresh route preview.');message('Atlas-owned browser is starting. Sign in there and browse within the explicit scope.');await webRefresh(true);},$('web-browser-start')));
  $('web-ws-start').addEventListener('click',()=>run(async()=>{const config=await webReviewed(webOperationConfig('websocket'));const result=await api('web/ws/start',{workspace:state?.id,config});webInvalidateContext('WebSocket connected. A new operation needs a fresh route preview.');await webRefresh(true);$('web-ws-select').value=result.id;webMessageView();message('Scoped WebSocket connected. Messages feed assessment evidence.');}));
  $('web-ws-send').addEventListener('click',()=>run(async()=>{await api('web/ws/send',{workspace:state?.id,id:$('web-ws-select').value,message:$('web-ws-message').value,binary:$('web-ws-binary').checked});await webRefresh(true);}));
  $('web-ws-stop').addEventListener('click',()=>run(async()=>{await api('web/ws/stop',{workspace:state?.id,id:$('web-ws-select').value});await webRefresh(true);}));
  $('web-ws-select').addEventListener('change',webMessageView);
  $('web-ws-finding').addEventListener('click',()=>run(async()=>{await api('web/ws/finding',{workspace:state?.id,id:$('web-ws-select').value,message_id:$('web-ws-evidence').value,title:$('web-ws-finding-title').value,severity:$('web-ws-severity').value,detail:$('web-ws-detail').value});message('WebSocket assertion saved directly to assessment Findings with message evidence.');await webRefresh(true);}));
  $('web-oob-start').addEventListener('click',()=>run(async()=>{const result=await api('web/oob/start',{workspace:state?.id,config:{...webConfig(),bind_address:$('web-oob-bind').value,oob_port:Number($('web-oob-port').value),dns_port:Number($('web-oob-dns-port').value),dns_domain:$('web-oob-domain').value,callback_origin:$('web-oob-advertise').value,allow_remote_listener:$('web-oob-remote').checked}});await webRefresh(true);$('web-oob-select').value=result.id;message('Bounded owner-controlled interaction receiver started.');}));
  $('web-oob-issue').addEventListener('click',()=>run(async()=>{const result=await api('web/oob/issue',{workspace:state?.id,id:$('web-oob-select').value,config:webRequestConfig(),parameter:$('web-parameter').value});$('web-oob-token').textContent=JSON.stringify(result,null,2);message('Token issued transiently. Matching HTTP/DNS interactions save evidence and findings automatically.');}));
  $('web-oob-stop').addEventListener('click',()=>run(async()=>{await api('web/oob/stop',{workspace:state?.id,id:$('web-oob-select').value});clear('web-oob-token');await webRefresh(true);}));
  $('web-refresh').addEventListener('click',()=>run(async()=>{needsWorkspace();await load(state.id);show('map');message('Showing collected network and web evidence. Logical resources are not physical wiring.');}));
  if(window.atlasOperatorRefresh)window.atlasOperatorRefresh();await webRefresh(true);setInterval(()=>{if(['web','findings','map','discovery'].includes(currentView))run(webRefresh);},1500);
});
