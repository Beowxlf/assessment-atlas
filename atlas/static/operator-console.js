'use strict';
let embeddedQueue=Promise.resolve(),terminalQueue=Promise.resolve();
let consoleWorkspace='',terminalId='',terminalCursor=0,terminalView=null,terminalPoll=false,terminalPlan=null;
let embeddedId='',embeddedPoll=false,embeddedScope=null,terminalStarting=false,embeddedStarting=false,terminalAvailable=false;
let consoleSource='terminal-selection',consoleReady=false,consoleNativeId='',terminalEvidenceId='';
function terminalDocument(){
  // xterm creates two document-local renderer styles. Give only that instance
  // a style nonce, without granting inline scripts or changing global DOM APIs.
  const styleNonce=document.querySelector('meta[name="atlas-style-nonce"]')?.content;
  if(!styleNonce||!(/^[A-Za-z0-9_-]{32}$/).test(styleNonce))throw new Error('Terminal style policy is unavailable. Reload Atlas before opening a terminal.');
  const bound=new Map();
  return new Proxy(document,{get(target,key){
    if(key==='createElement'){
      if(!bound.has(key))bound.set(key,(name,options)=>{const node=target.createElement(name,options);if(node.localName==='style')node.nonce=styleNonce;return node;});
      return bound.get(key);
    }
    const value=Reflect.get(target,key,target);
    if(typeof value!=='function')return value;
    if(!bound.has(key))bound.set(key,value.bind(target));
    return bound.get(key);
  }});
}
function consoleTab(name){
  for(const tab of ['terminal','browser','evidence'])$('console-'+tab).hidden=tab!==name;
  document.querySelectorAll('[data-console-tab]').forEach(button=>{button.classList.toggle('selected',button.dataset.consoleTab===name);button.setAttribute('aria-pressed',String(button.dataset.consoleTab===name));});
}
function consoleControls(){
  if(!consoleReady)return;
  $('terminal-open').disabled=!terminalAvailable||!!terminalId||terminalStarting;
  $('terminal-stop').disabled=!terminalId;
  $('terminal-selection').disabled=!terminalView?.getSelection();
  $('terminal-run').disabled=!terminalPlan||!!terminalId||terminalStarting;
  $('terminal-ports-label').hidden=$('terminal-profile').value!=='service-enumeration';
  $('terminal-url-label').hidden=$('terminal-profile').value!=='http-headers';
  $('embedded-start').querySelector('button').disabled=!!embeddedId||embeddedStarting;
  for(const input of $('embedded-start').querySelectorAll('input,textarea'))input.disabled=!!embeddedId||embeddedStarting;
  $('embedded-controls').hidden=!embeddedId;
}
function consoleInvalidatePlan(){
  terminalPlan=null;$('terminal-operation-authorized').checked=false;
  $('terminal-plan').textContent='';$('terminal-plan-summary').textContent='Preview this target and route before running.';consoleControls();
}
async function consolePrepareTerminal(node,address){
  needsWorkspace();if(!consoleReady)throw new Error('The operator console is still loading.');
  if(terminalId)throw new Error('Stop the current terminal before preparing another target.');
  const workspace=state.id;
  await operatorOpen({view:'console',consoleTab:'terminal'});
  if(state?.id!==workspace)return;
  const members=new Set(node.members),ports=new Set();
  for(const observation of state.observations){const value=observation.value;
    if(observation.kind==='service association'&&value&&typeof value==='object'&&(members.has(observation.subject)||members.has(observation.target))&&value.protocol==='tcp'&&value.state==='open'){
      const port=Number(value.portid);if(Number.isInteger(port)&&port>=1&&port<=65535)ports.add(port);
    }
  }
  const known=[...ports].sort((a,b)=>a-b),selected=[];
  for(const port of known){if([...selected,port].join(',').length>300)break;selected.push(port);}
  $('terminal-target').value=address;$('terminal-profile').value=selected.length?'service-enumeration':'tcp-discovery';
  $('terminal-ports').value=selected.join(',');$('terminal-url').value='';$('terminal-authorized').checked=false;
  $('console-subject').value=node.members[0];consoleInvalidatePlan();$('terminal-operations').open=true;$('terminal-target').focus();
  message('Terminal prepared for '+node.label+' · '+address+'. '+(selected.length?selected.length+' reported open TCP ports prepared'+(known.length>selected.length?'; '+(known.length-selected.length)+' ports omitted by the input limit':'')+'. ':'')+'Review the interface, scope and operation, then preview the route. Nothing has started.');
}
async function consolePrepareBrowser(node,entry){
  needsWorkspace();if(!consoleReady)throw new Error('The operator console is still loading.');
  if(embeddedId)throw new Error('Stop the current embedded browser before preparing another target.');
  const workspace=state.id;
  await operatorOpen({view:'console',consoleTab:'browser'});
  if(state?.id!==workspace)return;
  const url=new URL(entry.url);url.search='';url.hash='';
  $('embedded-start').reset();$('embedded-url').value=url.href;$('embedded-prefix').value='/';$('embedded-ca').value='';$('embedded-authorized').checked=false;
  $('embedded-input').value='';$('embedded-location').value='';$('console-subject').value=node.members[0];$('embedded-setup').open=true;$('embedded-url').focus();
  message('Embedded browser prepared. '+entry.basis+'. Review target scope and authorize this session before starting.');
}
async function terminalStatus(){
  if(!state||terminalPoll||!consoleReady)return;terminalPoll=true;const workspace=state.id,id=terminalId;
  try{
    const result=await api('terminal/status?workspace='+encodeURIComponent(workspace)+(id?'&id='+id+'&cursor='+terminalCursor:''));
    if(state?.id!==workspace||terminalId!==id)return;
    if(result.capabilities){const c=result.capabilities;terminalAvailable=c.linux&&c.unprivileged;
      $('terminal-readiness').textContent=c.linux?(c.unprivileged?'Linux terminal ready. ':'Atlas must run as an unprivileged account. ')+Object.entries(c.tools).map(([tool,ready])=>tool+': '+(ready?'ready':'missing')).join(' · '):'Terminal requires the Ubuntu/Linux server. Local web testing and evidence remain available.';
    }else{
      terminalEvidenceId=result.id;terminalCursor=result.cursor;terminalView?.write(Uint8Array.from(atob(result.data),c=>c.charCodeAt(0)));
      $('terminal-status').textContent=result.vantage+' · '+result.state+' · '+(result.reason||'');
      if(result.truncated)message('Earlier terminal output exceeded the transient display buffer. Original configured-operation files remain on the execution host.');
      if(result.state==='stopped'){terminalId='';const model=await api('workspace?id='+workspace);if(state?.id===workspace){state=model;render();}}
    }
  }catch(error){if(state?.id===workspace)$('terminal-status').textContent=error.message;}
  finally{terminalPoll=false;consoleControls();}
}
function consoleOperation(){const profile=$('terminal-profile').value;return {profile,target:$('terminal-target').value,timeout:Number($('terminal-timeout').value),...(profile==='service-enumeration'?{ports:$('terminal-ports').value}:{}),...(profile==='http-headers'?{url:$('terminal-url').value}:{})};}
function embeddedAction(action){
  needsWorkspace();if(!embeddedId)throw new Error('Start the embedded browser first.');const workspace=state.id,id=embeddedId;
  const task=embeddedQueue.then(async()=>{
    if(state?.id!==workspace||embeddedId!==id)return null;
    const result=await api('web/browser/action',{workspace,id,action});if(state?.id!==workspace||embeddedId!==id)return null;
    $('embedded-screen').src='data:image/jpeg;base64,'+result.image;$('embedded-screen').hidden=false;
    $('embedded-status').textContent='Running on Atlas host · '+result.url;return result;
  });embeddedQueue=task.catch(()=>{});return task;
}
async function consoleRefresh(){
  if(!consoleReady)return;const current=state?.id||'';
  if(consoleWorkspace!==current){
    const previous=consoleWorkspace,terminal=terminalId,browser=embeddedId;consoleWorkspace=current;
    consoleNativeId='';terminalEvidenceId='';terminalId='';terminalCursor=0;embeddedId='';embeddedScope=null;
    $('terminal-authorized').checked=false;$('embedded-start').reset();$('embedded-url').value='';$('embedded-ca').value='';
    $('terminal-target').value='';$('terminal-ports').value='';$('terminal-url').value='';$('embedded-input').value='';$('embedded-location').value='';
    $('console-text').value='';$('console-title').value='';$('embedded-screen').hidden=true;$('embedded-screen').removeAttribute('src');$('embedded-setup').open=true;
    $('terminal-status').textContent='';$('embedded-status').textContent='No browser running. Review the target scope, then start a session.';
    terminalView?.reset();consoleInvalidatePlan();
    if(previous){if(terminal)await api('terminal/stop',{workspace:previous,id:terminal}).catch(()=>{});if(browser)await api('web/browser/stop',{workspace:previous,id:browser,config:{}}).catch(()=>{});}
    if(state?.id!==current)return;
    if(current&&window.atlasExecutionStatus){window.atlasExecutionStatus().then(status=>{if(state?.id===current)$('console-vantage').textContent='Execution server: '+status.host.name+' · '+status.host.platform+'. Connect the HTB VPN on that server; the computer viewing this page supplies no route to it. Typed terminal operations check their selected interface. Embedded browsing here uses the server’s current routing.';}).catch(error=>{if(state?.id===current)$('console-vantage').textContent='Execution host could not be described: '+error.message;});}
  }
  const selected=$('console-subject').value;clear('console-subject').append(new Option('Choose an existing identity',''));
  for(const identity of state?.entities||[])$('console-subject').append(new Option(identity.label+' · '+identity.kind,identity.id));
  if([...$('console-subject').options].some(option=>option.value===selected))$('console-subject').value=selected;
  consoleControls();if(state)await terminalStatus();
}
async function consoleStartTerminal(operation=false){
  needsWorkspace();if(terminalId||terminalStarting)throw new Error('Stop the current terminal before opening another.');
  if(operation&&!terminalPlan)throw new Error('Preview the operation first.');
  const workspace=state.id;terminalStarting=true;consoleControls();$('terminal-status').textContent='Starting on the Atlas execution host…';
  try{
    const data={workspace,authorized:$(operation?'terminal-operation-authorized':'terminal-authorized').checked,request_id:crypto.randomUUID().replaceAll('-','')};
    if(operation){Object.assign(data,{operation:consoleOperation(),interface:$('terminal-interface').value,digest:terminalPlan.digest,context_token:terminalPlan.context_token});consoleInvalidatePlan();$('terminal-plan-summary').textContent='Reviewed operation submitted. Preview again before another configured run.';}
    const result=await api('terminal/start',data);
    if(state?.id!==workspace){await api('terminal/stop',{workspace,id:result.id});return;}
    terminalId=result.id;terminalCursor=0;terminalView.reset();terminalView.focus();await terminalStatus();
  }finally{terminalStarting=false;consoleControls();}
}
run(async()=>{
  const response=await fetch('/operator-console.html');if(!response.ok)throw new Error('Operator console could not load.');
  const holder=el('div');holder.innerHTML=await response.text();document.querySelector('main').append(holder.firstElementChild);
  const nav=button('Operator console',()=>operatorOpen({view:'console'}));nav.dataset.view='console';document.querySelector('nav').append(nav);consoleReady=true;
  terminalView=new Terminal({cols:100,rows:24,scrollback:3000,allowProposedApi:false,convertEol:false,documentOverride:terminalDocument(),theme:{background:'#102c34',foreground:'#e6f2ed'}});terminalView.open($('terminal-screen'));
  terminalView.onSelectionChange(consoleControls);
  terminalView.onData(input=>{
    if(!terminalId)return;const workspace=state.id,id=terminalId;
    const task=terminalQueue.then(()=>{if(state?.id!==workspace||terminalId!==id)return;return api('terminal/input',{workspace,id,input});});
    terminalQueue=task.catch(error=>{if(state?.id===workspace&&terminalId===id)$('terminal-status').textContent=error.message;});
  });
  document.querySelectorAll('[data-console-tab]').forEach(button=>button.addEventListener('click',()=>consoleTab(button.dataset.consoleTab)));
  $('terminal-open').addEventListener('click',()=>run(()=>consoleStartTerminal()));
  $('terminal-run').addEventListener('click',()=>run(()=>consoleStartTerminal(true)));
  $('terminal-stop').addEventListener('click',()=>run(async()=>{if(!terminalId)return;const workspace=state.id,id=terminalId;await api('terminal/stop',{workspace,id});if(state?.id===workspace)await terminalStatus();}));
  $('terminal-selection').addEventListener('click',()=>{consoleSource='terminal-selection';consoleNativeId=terminalEvidenceId;$('console-text').value=terminalView.getSelection();consoleTab('evidence');$('console-title').focus();});
  $('terminal-operation').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    needsWorkspace();const workspace=state.id,operation=consoleOperation(),iface=$('terminal-interface').value;consoleInvalidatePlan();
    const result=await api('terminal/preview',{workspace,interface:iface,operation});
    if(state?.id!==workspace||JSON.stringify(operation)!==JSON.stringify(consoleOperation())||iface!==$('terminal-interface').value)return;
    terminalPlan=result;const display={...result};delete display.context_token;$('terminal-plan').textContent=JSON.stringify(display,null,2);
    $('terminal-plan-summary').textContent='Reviewed preview · '+result.plan.target+' · '+result.plan.profile+' · '+(result.route?'route '+result.route.interface+' from '+result.route.source:'Linux route check required')+' · '+result.plan.timeout+' seconds. Changes require a new preview; this review expires in '+(result.expires_in||60)+' seconds.';consoleControls();
    if(Number.isFinite(result.expires_in))setTimeout(()=>{if(terminalPlan===result){consoleInvalidatePlan();$('terminal-plan-summary').textContent='Execution review expired. Preview the current target and route again.';}},result.expires_in*1000);
  });});
  $('terminal-operation').addEventListener('input',consoleInvalidatePlan);
  $('embedded-start').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    needsWorkspace();if(embeddedId||embeddedStarting)throw new Error('Stop the current browser before starting another.');
    const workspace=state.id,url=new URL($('embedded-url').value);
    if(url.username||url.password||url.search||url.hash)throw new Error('Use a target URL without credentials, query or fragment.');
    const scope={workspace,url:url.href,prefix:$('embedded-prefix').value,ca:$('embedded-ca').value};embeddedStarting=true;consoleControls();$('embedded-status').textContent='Starting the scoped browser on the Atlas host…';
    try{
      const result=await api('web/browser/start',{workspace,config:{url:scope.url,origins:[{origin:url.origin,path_prefix:scope.prefix}],authorized:$('embedded-authorized').checked,embedded:true,headless:true,ca_pem:scope.ca,path_prefix:scope.prefix,max_seconds:1800,max_requests:500,vantage:'Atlas execution host embedded browser'}});
      if(state?.id!==workspace){await api('web/browser/stop',{workspace,id:result.id,config:{}});return;}
      embeddedId=result.id;embeddedScope=scope;consoleControls();await embeddedAction({kind:'screen'});$('embedded-setup').open=false;
      $('embedded-refresh').focus({preventScroll:true});
    }finally{embeddedStarting=false;consoleControls();}
  });});
  $('embedded-navigate').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    if(!embeddedScope)throw new Error('Start the embedded browser first.');
    const url=new URL($('embedded-location').value,embeddedScope.url);
    if(url.username||url.password)throw new Error('Page URLs cannot contain credentials.');
    await embeddedAction({kind:'navigate',url:url.href});$('embedded-screen').focus({preventScroll:true});
  });});
  $('embedded-refresh').addEventListener('click',()=>run(()=>embeddedAction({kind:'screen'})));
  $('embedded-read').addEventListener('click',()=>run(async()=>{const result=await embeddedAction({kind:'read'});if(!result)return;consoleSource='browser-selection';consoleNativeId=embeddedId;$('console-text').value=result.text;consoleTab('evidence');$('console-title').focus();}));
  $('embedded-stop').addEventListener('click',()=>run(async()=>{
    if(!embeddedId)return;const workspace=state.id,id=embeddedId;await api('web/browser/stop',{workspace,id,config:{}});if(state?.id!==workspace||embeddedId!==id)return;
    embeddedId='';embeddedScope=null;$('embedded-screen').hidden=true;$('embedded-screen').removeAttribute('src');$('embedded-input').value='';$('embedded-location').value='';$('embedded-authorized').checked=false;$('embedded-setup').open=true;
    $('embedded-status').textContent='Browser stopped. Collected evidence remains in the assessment.';consoleControls();
    const model=await api('workspace?id='+workspace);if(state?.id===workspace){state=model;render();}
  }));
  $('embedded-auth').addEventListener('click',()=>run(async()=>{
    if(!embeddedId||!embeddedScope)throw new Error('Start and sign in through the embedded browser first.');const scope={...embeddedScope};
    window.atlasResetInvestigationTest?.();
    $('web-scope').reset();$('web-request').reset();webClearAuth();$('web-session').value='';$('web-authorized').checked=false;
    for(const id of ['web-request-result','web-session-result','web-schema-result','web-proxy-credentials'])clear(id);
    await operatorOpen({view:'web',tab:'scanner',auth:true});if(state?.id!==scope.workspace)return;
    $('web-scope').reset();webClearAuth();$('web-url').value=scope.url;$('web-prefix').value=scope.prefix;$('web-ca').value=scope.ca;$('web-vantage').value='Atlas Linux server';$('web-session').value='';$('web-authorized').checked=false;
    $('web-auth-check').value='';$('web-auth-marker').value='';$('web-auth-origins').value='';
    message('Set the protected check URL and signed-in marker, select the active isolated browser, then use its signed-in cookies. Authentication is checked before auditing.');
  }));
  $('embedded-type').addEventListener('click',()=>run(async()=>{const text=$('embedded-input').value;$('embedded-input').value='';await embeddedAction({kind:'text',text});}));
  $('embedded-screen').addEventListener('click',event=>{const box=event.target.getBoundingClientRect();event.target.focus();run(()=>embeddedAction({kind:'click',x:Math.min(1279,Math.floor((event.clientX-box.left)*1280/box.width)),y:Math.min(799,Math.floor((event.clientY-box.top)*800/box.height))}));});
  $('embedded-screen').addEventListener('wheel',event=>{event.preventDefault();run(()=>embeddedAction({kind:'wheel',delta:Math.max(-800,Math.min(800,Math.round(event.deltaY)))}));},{passive:false});
  $('embedded-screen').addEventListener('keydown',event=>{
    if(event.key.length===1&&!event.ctrlKey&&!event.metaKey){event.preventDefault();event.stopPropagation();run(()=>embeddedAction({kind:'text',text:event.key}));return;}
    const key=event.key==='Tab'&&event.shiftKey?'Shift+Tab':event.ctrlKey&&['a','c','v'].includes(event.key)?'Control+'+event.key:event.key;
    if(['Enter','Backspace','Delete','Tab','Shift+Tab','Escape','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home','End','PageUp','PageDown','Control+a','Control+c','Control+v'].includes(key)){event.preventDefault();event.stopPropagation();run(()=>embeddedAction({kind:'key',key}));}
  });
  $('console-capture').addEventListener('submit',event=>{event.preventDefault();run(async()=>{
    needsWorkspace();requireEmptyRecordDraft();const workspace=state.id,subject=$('console-subject').value,title=$('console-title').value;
    const result=await api('capture-selection',{workspace,subject,title,text:$('console-text').value,source:consoleSource,native_id:consoleNativeId});
    if(state?.id!==workspace){message('Evidence saved to its original assessment. Reopen that workspace to draft the finding.');return;}
    state=result.workspace;render();requireEmptyRecordDraft();show('activity');
    $('record-kind').value='finding';$('record-subject').value=state.canonical[subject]||subject;$('record-title').value=title;$('record-evidence').value=result.observation_id;
    $('record-details').value='Observation: '+title+'\nEvidence: '+result.observation_id+'\n\nImpact, validation and limitations:\n\nRemediation and retest:';rememberRecordDraft();$('record-title').focus();
    message('Evidence saved. Review and save this finding draft; no impact is automatically asserted.');
  });});
  let resizeTimer;
  new ResizeObserver(()=>{const width=$('terminal-screen').clientWidth;if(!width)return;clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{
    const cols=Math.max(24,Math.min(200,Math.floor(width/9)));terminalView.resize(cols,24);
    if(terminalId)run(()=>api('terminal/resize',{workspace:state.id,id:terminalId,rows:24,cols}));
  },100);}).observe($('terminal-screen'));
  window.atlasConsoleRefresh=()=>run(consoleRefresh);await consoleRefresh();
  setInterval(()=>{
    if(terminalId)terminalStatus();
    if(embeddedId&&!embeddedPoll){embeddedPoll=true;const workspace=state.id;embeddedAction({kind:'screen'}).catch(error=>{if(state?.id===workspace)$('embedded-status').textContent=error.message;}).finally(()=>embeddedPoll=false);}
  },2000);
});
