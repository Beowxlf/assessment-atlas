'use strict';
let webWorkspace='',webCaptures=[],webPolling=false;
function webLines(id){return $(id).value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);}
function webConfig(){
  needsWorkspace();
  return {url:$('web-url').value,path_prefix:$('web-prefix').value,extra_origins:webLines('web-origins'),exclude_paths:webLines('web-exclude'),ca_pem:$('web-ca').value,authorized:$('web-authorized').checked,vantage:$('web-vantage').value,namespace:$('web-namespace').value,retain_body:$('web-retain').checked,max_requests:Number($('web-limit').value),max_seconds:Number($('web-seconds').value),delay_ms:Number($('web-delay').value),max_depth:Number($('web-depth').value),proxy_port:Number($('web-proxy-port').value)};
}
function webRequestConfig(){return {...webConfig(),request_url:$('web-request-url').value||$('web-url').value,method:$('web-method').value,headers:$('web-headers').value,body:$('web-body').value};}
async function webRefresh(){
  if(!$('web-runs'))return;
  if(webWorkspace!==(state?.id||'')){
    webWorkspace=state?.id||'';webCaptures=[];$('web-scope').reset();$('web-headers').value='';$('web-body').value='';$('web-url').value='';$('web-request-url').value='';clear('web-compare-left');clear('web-compare-right');clear('web-request-result');clear('web-comparison');clear('web-proxy-credentials');clear('web-intercepts');
  }
  if(!state){clear('web-runs').append(el('p','Create or select a workspace before configuring live tools.','muted'));return;}
  if(webPolling)return;webPolling=true;
  try{
    const id=state.id;const result=await api('web/status?workspace='+encodeURIComponent(id));if(state?.id!==id)return;
    clear('web-runs');
    for(const r of [...result.runs].reverse()){
      const row=el('div','','list-item');row.append(badge(r.state),el('strong',r.kind+' · '+r.requests+' requests'),el('p',r.reason||'Bounded collection in progress','subline'),button('Inspect plan and evidence references',()=>details('Web run '+r.kind,[r])));
      if(['running','queued'].includes(r.state)&&['crawl','payload','scanner'].includes(r.kind))row.append(button('Stop run',async()=>{await api('web/stop',{workspace:id,id:r.id});message('Stop requested. An in-flight request may finish; completed evidence remains saved.');}));
      $('web-runs').append(row);
    }
    if(!result.runs.length)$('web-runs').append(el('p','No native collection runs yet.','muted'));
    clear('web-proxy-status');const pending=new Set();
    for(const p of result.proxies){
      const row=el('div','','list-item');row.append(badge(p.state),el('strong','127.0.0.1:'+p.port+' · '+p.requests+' requests'));
      if(p.state==='running')row.append(button(p.intercept?'Turn interception off':'Intercept live requests',async()=>{await api('web/proxy/intercept',{workspace:id,id:p.id,enabled:!p.intercept});await webRefresh();}),button('Stop proxy / browser',async()=>{await api('web/proxy/stop',{workspace:id,id:p.id});clear('web-proxy-credentials');await webRefresh();}));
      $('web-proxy-status').append(row);
      for(const item of p.pending){
        pending.add(item.id);if(document.getElementById('intercept-'+item.id))continue;
        const card=el('article','','card');card.id='intercept-'+item.id;card.append(el('h3',item.method+' '+item.url),el('p','Transient request editor. No credentials or original message are saved by this editor.','muted'));
        const method=el('select');for(const name of ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])method.append(new Option(name,name));method.value=item.method;
        const headers=el('textarea');headers.value=item.headers.map(h=>h.name+': '+h.value).join('\n');const body=el('textarea');body.value=item.body;
        for(const [name,input] of [['Method',method],['Headers',headers],['Body',body]]){const label=el('label',name);label.append(input);card.append(label);}
        card.append(button('Forward edited request',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'forward',changes:{method:method.value,headers:headers.value,body:body.value}});card.remove();message('Request forwarded within scope.');}),button('Drop request',async()=>{await api('web/proxy/decide',{workspace:id,id:p.id,pending_id:item.id,action:'drop'});card.remove();message('Request dropped.');}));
        $('web-intercepts').append(card);
      }
    }
    for(const card of $('web-intercepts').children)if(!pending.has(card.id.replace('intercept-','')))card.remove();
    for(const browser of result.browsers)if(browser.error)$('web-proxy-status').append(el('p',browser.error,'muted'));
    if(currentView==='web'){
      const fresh=await api('workspace?id='+encodeURIComponent(id));if(state?.id===id&&fresh.observations.length!==state.observations.length){state=fresh;render();}
    }
  }finally{webPolling=false;}
}
window.atlasWebRefresh=()=>run(webRefresh);
run(async()=>{
  const response=await fetch('/web-tools.html');if(!response.ok)throw new Error('Web tools could not load.');
  const wrapper=el('div');wrapper.innerHTML=await response.text();document.querySelector('main').append(wrapper.firstElementChild);
  const nav=el('button','Web workbench');nav.dataset.view='web';nav.addEventListener('click',()=>{show('web');run(webRefresh);});document.querySelector('nav').append(nav);
  const foot=document.querySelector('.sidebar-foot');for(const node of [...foot.childNodes])if(node!==$('version'))node.remove();foot.prepend(document.createTextNode('Imports stay local. Live tools use your explicit scope.'));
  document.querySelectorAll('[data-web-tab]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.web-pane').forEach(p=>p.hidden=p.id!=='web-pane-'+b.dataset.webTab);document.querySelectorAll('[data-web-tab]').forEach(n=>n.classList.toggle('selected',n===b));}));
  $('web-crawl').addEventListener('submit',e=>{e.preventDefault();run(async()=>{await api('web/start',{workspace:state?.id,kind:'crawl',config:{...webConfig(),paths:webLines('web-paths'),crawl:$('web-follow').checked}});message('Bounded enumeration started. Partial results are saved as requests complete.');await webRefresh();});});
  $('web-common-paths').addEventListener('click',()=>$('web-paths').value='/robots.txt\n/sitemap.xml\n/favicon.ico\n/api\n/docs');
  $('web-request').addEventListener('submit',e=>{e.preventDefault();run(async()=>{const result=await api('web/request',{workspace:state?.id,config:webRequestConfig()});webCaptures.push({id:result.capture_id,label:result.event.request.method+' '+result.event.url+' · '+(result.event.response?.status||'failed')});for(const select of ['web-compare-left','web-compare-right']){clear(select);for(const capture of webCaptures)$(select).append(new Option(capture.label,capture.id));}$('web-compare-right').value=result.capture_id;clear('web-request-result').append(el('h3','Captured response'),el('pre',JSON.stringify(result.event.response||{error:result.event.error},null,2)));message('Bounded response inspected; normalized scoped evidence saved.');await webRefresh();});});
  $('web-compare').addEventListener('click',()=>run(async()=>{const result=await api('web/compare',{workspace:state?.id,left:$('web-compare-left').value,right:$('web-compare-right').value});$('web-comparison').textContent=(result.identical?'Responses are identical.':result.diff)+'\n'+result.limit;}));
  $('web-payload').addEventListener('submit',e=>{e.preventDefault();run(async()=>{await api('web/start',{workspace:state?.id,kind:'payload',config:{...webRequestConfig(),parameter:$('web-parameter').value,parameter_location:$('web-parameter-location').value,payloads:webLines('web-payloads')}});message('Selected-parameter baseline and bounded tests started.');await webRefresh();});});
  $('web-scanner-start').addEventListener('click',()=>run(async()=>{await api('web/start',{workspace:state?.id,kind:'scanner',config:webConfig()});message('Original response checks started; findings remain tool-reported.');await webRefresh();},$('web-scanner-start')));
  $('web-proxy-start').addEventListener('click',()=>run(async()=>{const result=await api('web/proxy/start',{workspace:state?.id,config:webConfig()});clear('web-proxy-credentials').append(el('p','Use only a separate test browser. Proxy credentials are transient and are not exported.'),el('pre','Proxy: http://127.0.0.1:'+result.port+'\nUsername: '+result.username+'\nPassword: '+result.password+'\nPublic CA SHA-256: '+result.CA_sha256),button('Download this public CA',async()=>{const response=await fetch('/api/web/ca?workspace='+encodeURIComponent(state.id)+'&id='+result.id);if(!response.ok)throw new Error('CA download failed');download(await response.text(),'atlas-isolated-proxy-ca.pem','application/x-pem-file');}));message('Scoped loopback proxy started. Existing browser/Burp trust and proxy settings are untouched.');await webRefresh();},$('web-proxy-start')));
  $('web-browser-start').addEventListener('click',()=>run(async()=>{await api('web/browser/start',{workspace:state?.id,config:webConfig()});message('Atlas-owned browser is starting. Sign in there and browse within the explicit scope.');await webRefresh();},$('web-browser-start')));
  $('web-refresh').addEventListener('click',()=>run(async()=>{needsWorkspace();await load(state.id);show('map');message('Showing collected network and web evidence. Logical resources are not physical wiring.');}));
  await webRefresh();setInterval(()=>{if(currentView==='web')run(webRefresh);},1500);
});
