'use strict';
const $ = id => document.getElementById(id);
let state = null, nonce = '', currentView = 'overview', pending = null, zoom = 1;
const NS = 'http://www.w3.org/2000/svg';
function el(tag, text = '', cls = '') { const n = document.createElement(tag); n.textContent = text; if (cls) n.className = cls; return n; }
function clear(id) { $(id).replaceChildren(); return $(id); }
function badge(text) { return el('span', text, 'badge ' + text); }
function button(text, handler, cls = '') { const b = el('button', text, cls); b.type = 'button'; b.addEventListener('click', () => run(handler, b)); return b; }
function message(text, error = false) { $('message').textContent = text; $('message').className = error ? 'error' : ''; }
async function run(fn, b) { if (b) b.disabled = true; try { await fn(); } catch (err) { message(err.message, true); } finally { if (b) b.disabled = false; } }
async function api(path, data) {
  const r = await fetch('/api/' + path, data ? {method:'POST', headers:{'Content-Type':'application/json','X-Atlas-Nonce':nonce}, body:JSON.stringify(data)} : {});
  const result = await r.json(); if (!r.ok) throw new Error(result.error || 'Request failed.'); return result;
}
function needsWorkspace() { if (!state) throw new Error('Create or choose a workspace first.'); }
function label(id) { return state?.entities.find(e => e.id === id)?.label || 'Entire engagement'; }
function canonical(id) { return state.canonical[id] || id; }
function show(view) {
  window.scrollTo({top:0,left:0});
  currentView = view; document.querySelectorAll('.view').forEach(s => s.hidden = s.id !== view);
  document.querySelectorAll('nav button').forEach(b => { b.classList.toggle('selected', b.dataset.view === view); if (b.dataset.view === view) b.setAttribute('aria-current','page'); else b.removeAttribute('aria-current'); });
  if (view === 'map') renderGraph();
  if (view === 'report') renderExportSelection();
  if(window.atlasOperatorShow)window.atlasOperatorShow(view);
}
async function refreshList(selected) {
  const workspaces = await api('workspaces'); clear('workspace').append(new Option('Choose a workspace',''));
  for (const w of workspaces) $('workspace').append(new Option(w.name,w.id));
  if (selected) $('workspace').value = selected;
  return workspaces;
}
async function load(id) {
  state = id ? await api('workspace?id=' + encodeURIComponent(id)) : null;
  localStorage.setItem('atlas-workspace',id || ''); pending = null; clear('import-preview'); render();
}
function render() {
  $('workspace-title').textContent = state?.name || 'Make the evidence connect.';
  $('scope').textContent = state?.scope || 'Import discoveries, explore relationships, and keep the reasoning behind every conclusion.';
  $('welcome').hidden = !!state; clear('summary'); clear('source-summary'); clear('health-summary');
  if (state) {
    const metrics = el('div','','metrics');
    for (const [value,text] of [[state.nodes.length,'Mapped identities'],[state.observations.length,'Evidence observations'],[state.findings.length,'Scanner assertions'],[state.records.filter(r=>r.status!=='complete').length,'Active assessment records']]) { const m=el('div','','metric'); m.append(el('strong',String(value)),el('span',text)); metrics.append(m); }
    $('summary').append(metrics);
    for (const source of state.imports) { const item=el('div','','list-item'); item.append(badge(source.source),el('strong',source.filename),el('div',source.imported_at + ' · ' + source.vantage,'subline')); item.append(button('Inspect source',()=>details(source.filename,[source]))); $('source-summary').append(item); }
    if (!state.imports.length) $('source-summary').append(el('p','No sources yet. Import a result file to begin.','muted'));
    $('health-summary').textContent = `${state.candidates.length} identity suggestions${state.candidates_limited?' (suggestion limit reached; manually select other candidates as needed)':''} · ${state.conflicts.length} sets of divergent observations. These remain visible until reviewed.`;
  }
  populateFilters(); renderGraph(); renderIdentities(); renderEvidence(); renderFindings(); renderRecords(); renderHistory(); renderExportSelection();
  if(window.atlasWebRefresh)window.atlasWebRefresh();
  if(window.atlasVulnerabilityRefresh)window.atlasVulnerabilityRefresh();
  if(window.atlasOperatorRefresh)window.atlasOperatorRefresh();
}
function options(id, nodes, emptyText) { const select=clear(id); if(emptyText) select.append(new Option(emptyText,'')); for(const n of nodes) select.append(new Option(n.label + ' · ' + n.kind,n.id)); }
function populateFilters() {
  const saved = ['edge-filter','source-filter'].map(id=>$(id).value);
  clear('edge-filter').append(new Option('All types','')); clear('source-filter').append(new Option('All sources & history',''));
  for(const kind of [...new Set((state?.edges||[]).map(e=>e.kind))].sort()) $('edge-filter').append(new Option(kind,kind));
  for(const source of state?.imports||[]) $('source-filter').append(new Option(source.filename + ' · ' + source.source,source.id));
  ['edge-filter','source-filter'].forEach((id,i)=>{if([...$(id).options].some(o=>o.value===saved[i])) $(id).value=saved[i];});
}
function filters() { return {kind:$('edge-filter').value,claim:$('claim-filter').value,import_id:$('source-filter').value}; }
function graphData(w) {
  const f=filters(); const observations=w.observations.filter(o=>(!f.kind||o.kind===f.kind)&&(!f.claim||o.status===f.claim)&&(!f.import_id||o.import_id===f.import_id));
  const keep=new Set(observations.flatMap(o=>[w.canonical[o.subject],w.canonical[o.target]]));
  const observationIds=new Set(observations.map(o=>o.id));
  const all=w.nodes.filter(n=>(!f.kind&&!f.claim&&!f.import_id)||keep.has(n.id));
  const nodes=all.slice(0,250), ids=new Set(nodes.map(n=>n.id));
  const edges=w.edges.filter(e=>ids.has(e.source)&&ids.has(e.target)&&observationIds.has(e.id)).slice(0,600);
  return {nodes,edges,omittedNodes:all.length-nodes.length,omittedEdges:w.edges.filter(e=>observationIds.has(e.id)).length-edges.length};
}
function svgEl(tag, attrs = {}, text = '') { const n=document.createElementNS(NS,tag); for(const [k,v] of Object.entries(attrs)) n.setAttribute(k,String(v)); n.textContent=text; return n; }
function makeGraph(w,interactive=true) {
  const data=graphData(w); const svg=svgEl('svg',{xmlns:NS,role:'img','aria-label':'Evidence map. Select a node or typed connection to inspect its evidence.'});
  const web=w.nodes.some(n=>n.kind.startsWith('web '));
  const columns=web?[['device','hop'],['interface'],['service','application','web origin'],['web resource'],['subnet','web parameter']]:[['device','hop'],['interface'],['service','application'],['subnet']];
  const viewWidth=columns.length*300;
  const points={}; const groups=columns.map(kinds=>data.nodes.filter(n=>kinds.includes(n.kind))); const rows=Math.max(3,...groups.map(g=>g.length));
  const height=Math.max(450,rows*95+90); svg.setAttribute('viewBox',`0 0 ${viewWidth} ${height}`); svg.setAttribute('data-height',height);
  const width=interactive?Math.max(650,($('graph').clientWidth||1200)*zoom):1200;svg.setAttribute('width',width);svg.setAttribute('height',height*width/viewWidth);
  const defs=svgEl('defs');const marker=svgEl('marker',{id:'arrow',viewBox:'0 0 10 10',refX:10,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'}); marker.append(svgEl('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#6e8987'}));defs.append(marker);svg.append(defs);
  groups.forEach((nodes,col)=>{const x=150+col*300;svg.append(svgEl('text',{x,y:30,'text-anchor':'middle',class:'column-label'},(web?['DEVICES / HOPS','INTERFACES','SERVICES / ORIGINS','WEB RESOURCES','SUBNETS / PARAMETERS']:['DEVICES / HOPS','INTERFACES','SERVICES / APPLICATIONS','SUBNETS / ROUTES'])[col]));nodes.forEach((n,row)=>points[n.id]={x,y:85+row*95});});
  for(const edge of data.edges) {
    const a=points[edge.source],b=points[edge.target]; if(!a||!b) continue;
    const group=svgEl('g');const dx=b.x-a.x,dy=b.y-a.y,distance=Math.hypot(dx,dy)||1; const attrs={x1:a.x,y1:a.y,x2:b.x-dx/distance*30,y2:b.y-dy/distance*30,class:edge.status,'marker-end':'url(#arrow)'};
    group.append(svgEl('line',attrs));
    if(interactive) {const hit=svgEl('line',{...attrs,'marker-end':'none',class:'edge-focus',tabindex:0,role:'button','aria-label':edge.kind + ', ' + edge.status + '. Inspect evidence.'}); const open=()=>observationDetails(edge);hit.addEventListener('click',open);hit.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open();}});hit.append(svgEl('title',{},edge.kind + ' · ' + edge.status));group.append(hit);}
    svg.append(group);
  }
  for(const node of data.nodes){const p=points[node.id];if(!p)continue;const g=svgEl('g',{transform:`translate(${p.x},${p.y})`,class:'node '+node.kind,tabindex:interactive?0:-1,role:'button','aria-label':node.label+', '+node.kind});
    if(node.kind==='interface'||node.kind==='subnet')g.append(svgEl('rect',{x:-26,y:-22,width:52,height:44,rx:8}));else g.append(svgEl('circle',{r:25}));
    g.append(svgEl('text',{'text-anchor':'middle',y:5},({device:'●',hop:'◌',interface:'▤',subnet:'▦',service:'◆',application:'◇'})[node.kind]));g.append(svgEl('text',{'text-anchor':'middle',y:46},node.label.length>30?node.label.slice(0,27)+'…':node.label));g.append(svgEl('title',{},node.labels.join(' / ')+' · '+node.kind));
    if(interactive){g.addEventListener('click',()=>nodeDetails(node));g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();nodeDetails(node);}});}svg.append(g);
  }
  return {svg,data};
}
function renderGraph(){clear('graph');if(!state){$('graph').append(el('div','Choose a workspace to inspect the map.','empty'));return;}const {svg,data}=makeGraph(state);$('graph').append(svg);if(!data.nodes.length)$('graph').append(el('div','No evidence matches these filters.','empty'));$('map-note').textContent=`${data.nodes.length} identities · ${data.edges.length} typed observations. ${data.omittedNodes||data.omittedEdges?`${data.omittedNodes} identities and ${data.omittedEdges} connections omitted by display limits; filter by source to narrow the view.`:'All matching identities shown.'}`;}
function details(title,objects){$('detail-title').textContent=title;clear('detail-body');for(const item of objects)$('detail-body').append(el('pre',JSON.stringify(item,null,2)));$('detail-dialog').showModal();}
function observationDetails(o){const source=state.imports.find(i=>i.id===o.import_id);details(o.kind,[{...o,subject_label:label(o.subject),target_label:o.target?label(o.target):null},source||{}]);}
function nodeDetails(n){const obs=state.observations.filter(o=>canonical(o.subject)===n.id||(o.target&&canonical(o.target)===n.id));$('detail-title').textContent=n.label;clear('detail-body').append(el('p',n.kind+' · '+n.labels.join(' / ')),el('pre',JSON.stringify({identity:n.id,members:n.members,addresses:n.addresses,namespace:n.namespace},null,2)));for(const o of obs){const row=el('div','','list-item');row.append(badge(o.status),badge(o.basis),el('strong',o.kind),el('div',JSON.stringify(o.value),'subline'),button('Inspect evidence',()=>{ $('detail-dialog').close();observationDetails(o);}));$('detail-body').append(row);}const linked=[...state.findings,...state.records].filter(r=>r.subject&&canonical(r.subject)===n.id);if(linked.length){$('detail-body').append(el('h3','Linked findings and assessment activity'));for(const r of linked)$('detail-body').append(el('pre',JSON.stringify(r,null,2)));}$('detail-dialog').showModal();}
function renderIdentities(){options('identity-left',state?.nodes||[]);options('identity-right',state?.nodes||[]);options('record-subject',state?.nodes||[],'Entire engagement');clear('candidates');clear('decisions');for(const c of state?.candidates||[]){const row=el('div','','list-item');row.append(el('p',c.reason,'muted'),button('Review this pair',()=>{$('identity-left').value=c.left;$('identity-right').value=c.right;$('identity-reason').focus();}),button('Inspect first',()=>nodeDetails(state.nodes.find(n=>n.id===c.left))),button('Inspect second',()=>nodeDetails(state.nodes.find(n=>n.id===c.right))));$('candidates').append(row);}for(const d of state?.decisions||[]){const row=el('div','','list-item');row.append(el('strong',label(d.left)+' ↔ '+label(d.right)),el('p',d.reason,'subline'),badge(d.active?'linked':'undone'));if(d.active)row.append(button('Undo link',async()=>{state=await api('undo',{workspace:state.id,decision:d.id});render();message('Identity link undone. All evidence is retained.');}));$('decisions').append(row);}if(!state?.decisions.length)$('decisions').append(el('p','No identity links recorded.','muted'));}
function renderEvidence(){clear('imports-list');clear('evidence-list');for(const source of state?.imports||[]){const card=el('article','','card');card.append(el('h2',source.filename),badge(source.source),el('p',source.warnings.join(' '),'muted'),button('Inspect provenance',()=>details(source.filename,[source])));$('imports-list').append(card);}const query=$('evidence-search').value.toLowerCase();const data=(state?.observations||[]).filter(o=>(JSON.stringify(o)+' '+label(o.subject)).toLowerCase().includes(query));const wrap=el('div','','table-wrap');const table=el('table');const head=el('tr');for(const h of ['Subject','Observation','Meaning','Collected / position','Inspect'])head.append(el('th',h));const thead=el('thead');thead.append(head);table.append(thead);const body=el('tbody');for(const o of data.slice(0,500)){const row=el('tr');row.append(el('td',label(o.subject)),el('td',o.kind));const meaning=el('td');meaning.append(badge(o.status),badge(o.basis));row.append(meaning,el('td',(o.collected_at||'Unknown time')+' · '+o.vantage));const action=el('td');action.append(button('Evidence',()=>observationDetails(o)));row.append(action);body.append(row);}table.append(body);wrap.append(table);$('evidence-list').append(el('p',`${data.length} matching observations; showing up to 500. Search narrows the list.`,'muted'),wrap);}
function reviewForm(record,collection){const form=el('form','','review-form');const status=el('select');for(const s of ['open','in progress','complete','needs retest','accepted risk','false positive'])status.append(new Option(s,s));status.value=record.status;const note=el('input');note.placeholder='Review note and evidence';note.required=true;note.maxLength=3000;const l1=el('label','Status');l1.append(status);const l2=el('label','Review note');l2.append(note);const submit=el('button','Save review');form.append(l1,l2,submit);form.addEventListener('submit',e=>{e.preventDefault();run(async()=>{state=await api('review',{workspace:state.id,collection,id:record.id,status:status.value,note:note.value});render();message('Review saved with history. Source validation labels are unchanged.');},submit);});return form;}
function findingControls(f){
  if(f.origin==='public-advisory-match'){
    const matched=state.observations.filter(o=>o.import_id===f.import_id);const refs=new Set(matched.flatMap(o=>o.value.inventory_evidence_refs||[]));
    const inventory=state.observations.filter(o=>refs.has(o.id));const sourceIds=new Set([f.import_id,...inventory.map(o=>o.import_id)]);
    details(f.title+' · advisory and inventory evidence',[{finding:f,source_captures:state.imports.filter(s=>sourceIds.has(s.id)),observations:[...matched,...inventory],limit:'Inferred version/advisory correlation. Public source facts and inventory evidence are retained; target impact and patch status require validation.'}]);return;
  }
  const observations=state.observations.filter(o=>o.import_id===f.import_id);const tests=observations.filter(o=>o.kind==='selected parameter test');
  const ids=new Set(tests.flatMap(o=>[o.value.baseline_event_id,...(o.value.control_event_ids||[])]).filter(Boolean));
  const correlations=new Set(observations.filter(o=>o.kind==='out-of-band interaction').map(o=>o.value.correlation_id));
  for(const o of state.observations.filter(o=>o.kind==='out-of-band interaction'&&correlations.has(o.value.correlation_id))){if(o.value.probe_capture_id)ids.add(o.value.probe_capture_id);if(o.value.baseline_event_id)ids.add(o.value.baseline_event_id);ids.add(state.imports.find(s=>s.id===o.import_id)?.event_id);}
  const imports=state.imports.filter(s=>s.id===f.import_id||ids.has(s.event_id));const sourceIds=new Set(imports.map(s=>s.id));
  details(f.title+' · test and controls',[{finding:f,source_captures:imports,observations:state.observations.filter(o=>sourceIds.has(o.import_id)),limit:'Source assertions remain scanner-reported. Authentication context is a checked session, not proof that every endpoint requires login.'}]);
}
function renderFindings(){clear('finding-list');for(const f of state?.findings||[]){const card=el('article','','card');card.append(badge(f.severity),badge(f.validation),el('h2',f.title),el('p',label(f.subject)+' · '+f.external_id,'muted'),el('p',f.description),button('Inspect source',()=>details(f.title,[f,state.imports.find(s=>s.id===f.import_id)||{}])),button(f.origin==='public-advisory-match'?'Inspect advisory and inventory evidence':'Inspect test and controls',()=>findingControls(f)),reviewForm(f,'findings'));if(f.origin==='public-advisory-match'){const context=state.observations.find(o=>o.import_id===f.import_id&&o.kind==='vulnerability match')?.value.priority_context;if(context){const kev=context.known_exploited===true?'KEV source lists exploitation in the wild':context.known_exploited===false?'Not listed in the captured complete KEV catalog':'KEV coverage unknown';card.append(el('p',kev+' · source dates/authenticity are retained in evidence','subline'));for(const score of context.epss||[])card.append(el('p',score.id+' · EPSS '+(score.probability*100).toFixed(2)+'% · percentile '+(score.percentile*100).toFixed(2)+' · '+(score.score_date||'date unknown')+(score.stale_or_unknown_date?' · stale/unknown date':'')+' · probability context, separate from severity','subline'));}}if(f.review_notes)card.append(el('p',f.review_notes,'subline'));$('finding-list').append(card);}if(!state?.findings.length)$('finding-list').append(el('div','No source-reported findings yet. Scan reviewed software or import results to begin.','empty'));}
function renderRecords(){clear('records-list');for(const r of [...(state?.records||[])].reverse()){const row=el('div','','list-item');row.append(badge(r.kind),badge(r.status),el('h3',r.title),el('p',r.details),el('p',label(r.subject)+' · Evidence: '+(r.evidence_refs||'Not supplied'),'subline'),reviewForm(r,'records'));$('records-list').append(row);}if(!state?.records.length)$('records-list').append(el('p','No activity yet. Record a question or next test.','muted'));}
function renderHistory(){clear('history');for(const item of [...(state?.history||[])].reverse())$('history').append(el('div',item.at+' · '+item.action+' · '+item.detail,'list-item'));}
function renderExportSelection(){const f=filters();$('export-selection').textContent=`Selection: ${f.kind||'all connection types'} · ${f.claim||'all claim states'} · ${f.import_id?state?.imports.find(i=>i.id===f.import_id)?.filename:'all source history'}. Identity and assessment context are retained.`;}
async function exportState(){needsWorkspace();return api('export',{workspace:state.id,identifiers:$('export-identifiers').checked,...filters()});}
function download(content,name,type){const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const a=el('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);}
async function exportSvg(){const w=await exportState();const saved=zoom;zoom=1;const {svg,data}=makeGraph(w,false);zoom=saved;const metadata=svgEl('metadata',{},JSON.stringify({export:w.export,display_limits:{omitted_nodes:data.omittedNodes,omitted_edges:data.omittedEdges},sources:w.imports,observations:w.observations.filter(o=>data.edges.some(e=>e.id===o.id))}));svg.prepend(metadata);svg.setAttribute('width','1200');svg.setAttribute('height',svg.getAttribute('data-height'));for(const n of svg.querySelectorAll('line')){n.setAttribute('stroke','#6e8987');n.setAttribute('stroke-width','2');if(n.classList.contains('inferred'))n.setAttribute('stroke-dasharray','7 5');if(n.classList.contains('unknown'))n.setAttribute('stroke-dasharray','2 5');}for(const n of svg.querySelectorAll('circle,rect')){n.setAttribute('fill','#eaf5ef');n.setAttribute('stroke','#6e8987');}for(const n of svg.querySelectorAll('text')){n.setAttribute('font-family','sans-serif');n.setAttribute('font-size','12');n.setAttribute('fill','#173b43');}download(new XMLSerializer().serializeToString(svg),'assessment-map.svg','image/svg+xml');message('Map downloaded with evidence metadata and display-limit information.');}
function newDialog(){$('new-dialog').showModal();$('new-name').focus();}
document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.view)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.go)));
$('new-workspace').addEventListener('click',newDialog);$('create-first').addEventListener('click',newDialog);$('cancel-new').addEventListener('click',()=>$('new-dialog').close());$('close-detail').addEventListener('click',()=>$('detail-dialog').close());
$('workspace').addEventListener('change',()=>run(()=>load($('workspace').value)));
$('new-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{state=await api('create',{name:$('new-name').value,scope:$('new-scope').value});localStorage.setItem('atlas-workspace',state.id);await refreshList(state.id);render();$('new-dialog').close();$('new-form').reset();show('import');message('Workspace created. Preview a file to begin.');});});
$('demo').addEventListener('click',()=>run(async()=>{state=await api('demo',{});localStorage.setItem('atlas-workspace',state.id);await refreshList(state.id);render();show('map');message('Synthetic example loaded. Every source and finding is invented for training.');},$('demo')));
['edge-filter','claim-filter','source-filter'].forEach(id=>$(id).addEventListener('change',()=>{zoom=1;renderGraph();renderExportSelection();}));
$('zoom-in').addEventListener('click',()=>{zoom=Math.min(4,zoom*1.25);renderGraph();});$('zoom-out').addEventListener('click',()=>{zoom=Math.max(.5,zoom/1.25);renderGraph();});$('reset-map').addEventListener('click',()=>{zoom=1;renderGraph();});
$('evidence-search').addEventListener('input',renderEvidence);
$('reconcile-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{needsWorkspace();state=await api('reconcile',{workspace:state.id,left:$('identity-left').value,right:$('identity-right').value,reason:$('identity-reason').value});$('identity-reason').value='';render();message('Identities linked by your recorded decision. Conflicting and historical observations remain available.');});});
$('record-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{needsWorkspace();state=await api('record',{workspace:state.id,kind:$('record-kind').value,subject:$('record-subject').value,title:$('record-title').value,details:$('record-details').value,evidence_refs:$('record-evidence').value,status:$('record-status').value});$('record-form').reset();render();message('Assessment record saved.');});});
$('import-form').addEventListener('input',()=>{pending=null;clear('import-preview');});
$('import-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{needsWorkspace();const file=$('import-file').files[0];if(!file)throw new Error('Choose a result file.');if(file.size>8*1024*1024)throw new Error('File exceeds the 8 MiB limit.');const content=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(await file.arrayBuffer());pending={workspace:state.id,filename:file.name,content,source:$('import-source').value,context:{vantage:$('import-vantage').value,namespace:$('import-namespace').value,collected_at:$('import-time').value,source_version:$('import-version').value}};const result=await api('preview',pending);clear('import-preview').append(el('h2','Preview: '+file.name),el('p',`${result.entities} entities · ${result.observations} observations · ${result.findings} findings`),el('p',result.warnings.join(' '),'muted'),el('pre',JSON.stringify(result.sample,null,2)),button('Save this import',async()=>{if(!pending)throw new Error('Preview the file again.');const result=await api('import',pending);state=result.workspace;pending=null;clear('import-preview');render();message(result.duplicate?'Identical import already saved; no duplicate observations added.':'Import saved. Inspect the map and review any identity suggestions.');},'primary'));message('Preview ready. No changes have been saved yet.');});});
$('manual-template').addEventListener('click',()=>download(JSON.stringify({format:'atlas-evidence/1',source_version:'manual 1',entities:[{key:'router',label:'Synthetic router',kind:'device',addresses:['192.0.2.1']},{key:'peer',label:'Synthetic peer',kind:'device',addresses:['192.0.2.20']}],observations:[{subject:'router',target:'peer',kind:'local neighbor',status:'unknown',basis:'manual',value:{reason:'Replace with collected evidence and its limits'},collected_at:null}],findings:[]},null,2),'common-evidence.json','application/json'));
$('preview-export').addEventListener('click',()=>run(async()=>{const w=await exportState();$('export-preview').textContent=JSON.stringify({manifest:w.export,inventory:w.nodes.slice(0,10),findings:w.findings.slice(0,10),evidence:w.observations.slice(0,10),sources:w.imports},null,2);message('Preview shows up to 10 items per section. Download includes all selected results.');}));
$('download-json').addEventListener('click',()=>run(async()=>download(JSON.stringify(await exportState(),null,2),'assessment-results.json','application/json')));
$('download-html').addEventListener('click',()=>run(async()=>{needsWorkspace();const response=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json','X-Atlas-Nonce':nonce},body:JSON.stringify({workspace:state.id,format:'html',identifiers:$('export-identifiers').checked,...filters()})});if(!response.ok)throw new Error((await response.json()).error);download(await response.text(),'assessment-report.html','text/html');}));
$('download-svg').addEventListener('click',()=>run(exportSvg));$('map-download').addEventListener('click',()=>{show('report');message('Review export selection and identifiers before downloading the map.');});
$('delete-workspace').addEventListener('click',()=>run(async()=>{needsWorkspace();await api('delete',{workspace:state.id,confirmation:$('delete-confirmation').value});state=null;$('delete-confirmation').value='';await refreshList();render();show('overview');message('Workspace deleted. Original files, downloads and backups outside this application are unchanged.');}));
run(async()=>{const session=await api('session');nonce=session.nonce;$('version').textContent='Version '+session.version;$('storage').textContent='Data folder: '+session.storage;const list=await refreshList();const saved=localStorage.getItem('atlas-workspace');const chosen=list.find(w=>w.id===saved)?.id||list[0]?.id||'';$('workspace').value=chosen;await load(chosen);show('overview');});
