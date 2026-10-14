'use strict';
let operatorWorkspace='',operatorTarget='',operatorInitialized=false;
const atlasTools=[
  {name:'Target table',group:'Discovery',description:'Review hosts, services, endpoints and source evidence.',view:'discovery',keywords:'cobalt strike targets enumeration inventory'},
  {name:'Import scan results',group:'Discovery',description:'Preview Nmap, Nessus, Nuclei and other collected evidence.',view:'import',keywords:'discovery enumeration network ports files offline'},
  {name:'Network map',group:'Discovery',description:'Explore observed relationships and unresolved identities.',view:'map',keywords:'topology graph route neighbors'},
  {name:'Web discovery',group:'Discovery',description:'Crawl scoped links and discover explicit paths.',view:'web',tab:'crawl',keywords:'burp target site map enumeration directories paths spider'},
  {name:'Software vulnerability scan',group:'Testing',description:'Match CPE/package inventory with NVD/OSV and retain KEV/EPSS context.',view:'vulnerability',keywords:'cve ghsa public databases advisory sbom'},
  {name:'Request replay',group:'Testing',description:'Edit, resend and compare scoped HTTP requests.',view:'web',tab:'request',keywords:'burp repeater http2 http3 headers response'},
  {name:'Web scanner',group:'Testing',description:'Run selected bounded checks with retained controls.',view:'web',tab:'scanner',keywords:'burp scanner audit active passive sql xss'},
  {name:'Parameter tests',group:'Testing',description:'Test one selected parameter with a baseline and explicit payloads.',view:'web',tab:'payload',keywords:'burp intruder fuzzing reflection'},
  {name:'Payload matrix',group:'Testing',description:'Configure multiple positions and bounded payload combinations.',view:'web',tab:'advanced',anchor:'web-positions',keywords:'burp intruder sniper pitchfork cluster bomb'},
  {name:'Proxy interception',group:'Testing',description:'Inspect and edit traffic through the scoped local proxy.',view:'web',tab:'proxy',keywords:'burp proxy intercept response'},
  {name:'Authenticated browser',group:'Testing',description:'Browse an isolated session and retain scoped traffic evidence.',view:'web',tab:'browser',keywords:'login sso browser cookies sessions'},
  {name:'Scan authentication',group:'Testing',description:'Build a login sequence or select a checked transient session.',view:'web',tab:'scanner',anchor:'web-auth-check',auth:true,keywords:'credentials cookie bearer csrf authenticated scans'},
  {name:'WebSocket replay',group:'Testing',description:'Capture, edit and replay bounded text/binary messages.',view:'web',tab:'protocols',anchor:'web-ws-url',keywords:'ws wss sockets messages'},
  {name:'Interaction receiver',group:'Testing',description:'Correlate owned HTTP/DNS callbacks with source requests.',view:'web',tab:'protocols',anchor:'web-oob-bind',keywords:'burp collaborator out of band oob blind dns'},
  {name:'Response comparison',group:'Analysis',description:'Compare two responses captured in this session.',view:'web',tab:'request',anchor:'web-compare-left',keywords:'burp comparer diff status'},
  {name:'Decoder',group:'Analysis',description:'Decode or transform transient text without executing it.',view:'web',tab:'advanced',anchor:'web-utility-input',keywords:'burp decoder base64 hex url json sha256'},
  {name:'Token sample analysis',group:'Analysis',description:'Measure sample distributions and duplicates with explicit limits.',view:'web',tab:'advanced',anchor:'web-utility-input',operation:'tokens',keywords:'burp sequencer entropy tokens'},
  {name:'API inventory',group:'Analysis',description:'Read an inert API schema and review endpoints before testing.',view:'web',tab:'scanner',anchor:'web-schema',keywords:'openapi graphql schema discovery'},
  {name:'Evidence library',group:'Assessment',description:'Trace observations to their retained source snapshots.',view:'evidence',keywords:'provenance sources signatures'},
  {name:'Finding review',group:'Assessment',description:'Review source assertions, validation gaps and retest history.',view:'findings',keywords:'vulnerabilities assessment issues'},
  {name:'Assessment activity',group:'Assessment',description:'Keep questions, decisions and next tests with evidence links.',view:'activity',keywords:'notes tasks record follow up'},
  {name:'Reports and exports',group:'Assessment',description:'Preview redactions and export the assessment.',view:'report',keywords:'handoff json printable report'}
];
function operatorArrangeNavigation(){
  if(!operatorInitialized)return;
  const nav=document.querySelector('nav');const more=$('extra-views');
  const titles={overview:'Workspace',discovery:'Discovery',tools:'Tools',findings:'Findings',evidence:'Evidence',report:'Reports'};
  for(const [view,title] of Object.entries(titles)){let b=nav.querySelector('[data-view="'+view+'"]');if(!b){b=button(title,()=>operatorOpen({view}));b.dataset.view=view;}b.textContent=title;nav.insertBefore(b,more);}
  for(const view of ['map','activity','import','web','vulnerability']){const b=nav.querySelector('[data-view="'+view+'"]');if(b&&!more.contains(b))more.append(b);}
  const parent={map:'discovery',activity:'evidence',import:'discovery',web:'tools',vulnerability:'tools'}[currentView];
  for(const b of nav.querySelectorAll('button'))b.classList.toggle('selected',b.dataset.view===currentView||b.dataset.view===parent);
}
async function operatorOpen(tool){
  if(!$('web-pane-crawl')&&tool.view==='web')throw new Error('Web tools are still loading. Try again in a moment.');
  show(tool.view);
  if(tool.view==='web'){
    await webRefresh(true);const tab=document.querySelector('[data-web-tab="'+(tool.tab||'crawl')+'"]');tab?.click();
    if(tool.auth){$('web-auth-settings').hidden=false;$('web-auth-toggle').setAttribute('aria-expanded','true');}
    if(tool.operation)$('web-utility-operation').value=tool.operation;
  }else if(tool.view==='vulnerability')await vulnRefresh(true);
  if(tool.anchor){const target=$(tool.anchor);if(target){for(let p=target.parentElement;p;p=p.parentElement)if(p.tagName==='DETAILS')p.open=true;target.scrollIntoView({block:'center'});target.focus();}}
  else {const heading=$(tool.view)?.querySelector('h1');if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}}
  operatorArrangeNavigation();
}
function operatorToolsView(container,query,compact=false){
  container.replaceChildren();const words=query.toLowerCase().trim().split(/\s+/).filter(Boolean);const matches=atlasTools.filter(t=>words.every(w=>(t.name+' '+t.group+' '+t.description+' '+t.keywords).toLowerCase().includes(w)));
  for(const tool of matches){const card=el(compact?'div':'article','',compact?'list-item':'card tool-card');card.append(el('p',tool.group,'eyebrow'),el('h2',tool.name),el('p',tool.description,'muted'),button('Open '+tool.name,async()=>{if($('tool-dialog').open)$('tool-dialog').close('navigate');await operatorOpen(tool);}));container.append(card);}
  if(!matches.length)container.append(el('p','No matching tool. Try a task such as discovery, replay, authentication, CVE, or decoder.','muted'));
  if(!compact)$('tools-count').textContent=matches.length+' available tools · opening a tool prepares its controls; collection starts only when you choose Start or Send.';
}
function operatorRelated(node){
  const members=new Set(node.members);for(const o of state.observations)if(members.has(o.subject)&&['service association','web service association','web origin','web resource'].includes(o.kind)&&o.target)members.add(o.target);
  return members;
}
function operatorURLs(node){
  const related=operatorRelated(node);const urls=[];
  for(const o of state.observations){if(!related.has(o.subject)&&!related.has(o.target))continue;const v=o.value;if(!v||typeof v!=='object')continue;
    for(const raw of [v.url,v.origin]){try{const u=new URL(raw);if(['http:','https:'].includes(u.protocol)&&!u.username&&!u.password&&!urls.some(x=>x.url===u.href))urls.push({url:u.href,basis:'Captured/source-reported URL; source status '+o.status});}catch{}}
    if(o.kind==='service association'&&['http','https','ssl/http'].includes(v.signature?.name)){
      const host=state.entities.find(e=>e.id===o.subject);const address=host?.addresses[0];const port=Number(v.portid);if(address&&Number.isInteger(port)&&port>0&&port<=65535){const scheme=v.signature.tunnel==='ssl'||v.signature.name!=='http'?'https':'http';const raw=scheme+'://'+(address.includes(':')?'['+address+']':address)+':'+port+'/';try{const u=new URL(raw);if(!urls.some(x=>x.url===u.href))urls.push({url:u.href,basis:'Draft from reported address/HTTP service; scheme and endpoint need review'});}catch{}}
    }
  }return urls.slice(0,20);
}
async function operatorPrepareWeb(entry){
  await operatorOpen({view:'web',tab:'crawl'});for(const id of ['web-scope','web-request','web-crawl','web-payload'])$(id).reset();$('web-url').value=new URL(entry.url).origin+'/';$('web-request-url').value=entry.url;$('web-session').value='';webClearAuth();$('web-authorized').checked=false;
  for(const id of ['web-auth-check','web-auth-marker','web-auth-origins','web-login-url','web-login-preflight','web-login-csrf','web-login-bearer','web-protected-marker','web-audit-requests','web-custom-checks','web-schema','web-positions','web-canary-path','web-canary-marker','web-canary-url'])$(id).value='';$('web-auth-settings').hidden=true;$('web-auth-toggle').setAttribute('aria-expanded','false');$('web-active-audit').checked=false;$('web-oob-select').value='';document.querySelectorAll('#web-checks input, #web-more-checks input').forEach(input=>input.checked=input.value==='passive');for(const id of ['web-request-result','web-session-result','web-schema-result'])clear(id);
  $('web-url').focus();message('Discovery target prepared. '+entry.basis+'. Review the exact URL, paths and authorization before collecting.');
}
async function operatorPrepareVulnerability(node){
  await operatorOpen({view:'vulnerability'});vulnSelected.clear();const original=node.members[0];$('vuln-filter').value=original;$('vuln-asset').value=original;$('vuln-sbom-asset').value=original;vulnInventoryView();
  message('Software inventory prepared for '+node.label+'. Review and select precise identities before scanning.');
}
function operatorTargetView(){
  operatorContextView();
  clear('discovery-selection');const node=state?.nodes.find(n=>n.id===operatorTarget);if(!node){$('discovery-selection').append(el('p','Select a target to inspect its evidence and prepare the next tool.','muted'));return;}
  const related=operatorRelated(node);const observations=state.observations.filter(o=>related.has(o.subject)||related.has(o.target));const sources=state.imports.filter(i=>observations.some(o=>o.import_id===i.id));const findings=state.findings.filter(f=>related.has(f.subject));
  $('discovery-selection').append(el('p','SELECTED TARGET','eyebrow'),el('h2',node.label),el('p',node.kind+' · '+(node.addresses.join(', ')||'Address not established'),'muted'),el('p',observations.length+' related observations · '+sources.length+' source snapshots · '+findings.length+' findings','subline'),button('Inspect target evidence',()=>nodeDetails(node)),button('Prepare software vulnerability scan',()=>operatorPrepareVulnerability(node)));
  for(const entry of operatorURLs(node))$('discovery-selection').append(el('p',entry.url+' · '+entry.basis,'subline'),button('Prepare web discovery',()=>operatorPrepareWeb(entry)));
  if(!operatorURLs(node).length)$('discovery-selection').append(el('p','No reviewed web URL yet. Open Web discovery to enter one explicitly.','muted'),button('Open Web discovery',()=>operatorOpen({view:'web',tab:'crawl'})));
  for(const source of sources.slice(0,5))$('discovery-selection').append(el('p',source.source+' · '+source.imported_at+' · '+source.vantage,'subline'));
  $('discovery-selection').append(el('p','Source names/addresses and graph relationships do not establish authorization or physical wiring. Tool handoffs prepare controls and never start a request.','muted'));
}
function operatorContextView(){const selected=state?.nodes.find(n=>n.id===operatorTarget);clear('operator-context');$('operator-context').hidden=!selected;if(selected)$('operator-context').append(el('span','Selected target: '+selected.label+' · '+selected.kind),button('Return to target',()=>operatorOpen({view:'discovery'})));}
function operatorDiscoveryView(){
  if(!$('discovery-targets'))return;const focused=document.activeElement?.closest('#discovery-targets button')?.dataset.target;const query=$('discovery-search').value.toLowerCase();const kind=$('discovery-kind').value;const nodes=(state?.nodes||[]).filter(n=>(!kind||n.kind===kind)&&(n.label+' '+n.labels.join(' ')+' '+n.addresses.join(' ')).toLowerCase().includes(query));
  clear('discovery-targets');const wrap=el('div','','table-wrap');const table=el('table');const thead=el('thead');const head=el('tr');for(const text of ['Target','Type / addresses','Evidence','Findings'])head.append(el('th',text));thead.append(head);table.append(thead);const body=el('tbody');
  const stats=new Map();for(const o of state?.observations||[]){const keys=new Set([state.canonical[o.subject]||o.subject,state.canonical[o.target]||o.target]);for(const key of keys){if(!key)continue;if(!stats.has(key))stats.set(key,{count:0,statuses:new Set()});const s=stats.get(key);s.count++;s.statuses.add(o.status);}}
  const findingCounts=new Map();for(const f of state?.findings||[]){const key=state.canonical[f.subject]||f.subject;findingCounts.set(key,(findingCounts.get(key)||0)+1);}
  for(const n of nodes.slice(0,250)){const row=el('tr');const choose=el('td');const b=button(n.label,()=>{operatorTarget=n.id;operatorDiscoveryView();});b.dataset.target=n.id;b.setAttribute('aria-pressed',String(operatorTarget===n.id));choose.append(b);const s=stats.get(n.id)||{count:0,statuses:new Set()};row.append(choose,el('td',n.kind+' · '+(n.addresses.join(', ')||'No address established')),el('td',s.count+' observations · '+[...s.statuses].join(', ')),el('td',String(findingCounts.get(n.id)||0)));if(operatorTarget===n.id)row.className='selected-target';body.append(row);}
  table.append(body);wrap.append(table);$('discovery-targets').append(el('p',nodes.length+' matching identities · showing up to 250. Imported and collected identities retain their original sources.','subline'),wrap);if(!nodes.length)$('discovery-targets').append(el('p',state?'No matching targets. Import discovery results or review your filters.':'Choose a workspace, then import discoveries or start scoped web discovery.','muted'));
  if(focused)for(const b of $('discovery-targets').querySelectorAll('button'))if(b.dataset.target===focused)b.focus({preventScroll:true});
  operatorTargetView();clear('operator-jobs');for(const job of [...(state?.web_runs||[])].reverse().slice(0,5)){
    const row=el('div','','list-item');row.append(badge(job.state),el('strong',job.kind),el('p',job.requests+' requests · '+(job.findings||0)+' findings · '+(job.reason||'Collection in progress'),'subline'),button('Inspect run',()=>details('Assessment run',[job])));
    if(['queued','running'].includes(job.state)&&['crawl','payload','scanner','matrix','vulnerability','vulnerability-refresh'].includes(job.kind))row.append(button('Stop this run',async()=>{await api(job.kind.startsWith('vulnerability')?'vulnerability/stop':'web/stop',{workspace:state.id,id:job.id});message('Stop requested. Completed evidence remains retained.');}));$('operator-jobs').append(row);
  }if(!(state?.web_runs||[]).length)$('operator-jobs').append(el('p','No collection jobs yet. Prepared tool handoffs appear here once you deliberately start them.','muted'));
}
window.atlasOperatorRefresh=()=>{
  if(!operatorInitialized)return;const changed=operatorWorkspace!==(state?.id||'');if(changed){operatorWorkspace=state?.id||'';operatorTarget='';$('discovery-search').value='';$('discovery-kind').value='';$('tools-search').value='';}
  operatorArrangeNavigation();operatorDiscoveryView();if(changed||!$('tools-list').children.length)operatorToolsView($('tools-list'),$('tools-search').value);
  operatorContextView();
};
window.atlasOperatorShow=()=>{operatorArrangeNavigation();if(currentView==='discovery')operatorDiscoveryView();};
run(async()=>{
  const main=document.querySelector('main');const discovery=el('section');discovery.id='discovery';discovery.className='view';discovery.hidden=true;
  const targetContext=el('div','','operator-context');targetContext.id='operator-context';targetContext.hidden=true;main.insertBefore(targetContext,$('message').nextSibling);
  const heading=el('div','','page-heading');const intro=el('div');intro.append(el('p','DISCOVER · REVIEW · PREPARE THE NEXT TEST','eyebrow'),el('h1','Discovery and enumeration'),el('p','Work from one target table. Inspect what is known, then send the selected context to the right tool.'));heading.append(intro,button('Import discoveries',()=>operatorOpen({view:'import'}),'primary'));discovery.append(heading);
  const actions=el('div','','workflow-actions');for(const [title,description,tool] of [['Bring in results','Import host, port and service discovery',{view:'import'}],['Enumerate a website','Scope and crawl links or explicit paths',{view:'web',tab:'crawl'}],['Check software','Review inventory and match public advisories',{view:'vulnerability'}]]){const card=el('article','','card');card.append(el('h2',title),el('p',description,'muted'),button('Open '+title,()=>operatorOpen(tool)));actions.append(card);}discovery.append(actions);
  const toolbar=el('div','','toolbar');const search=el('label','Find target');const input=el('input');input.id='discovery-search';input.type='search';input.placeholder='Name or address';search.append(input);const kind=el('label','Target type');const select=el('select');select.id='discovery-kind';for(const [value,title] of [['','All identities'],['device','Devices'],['service','Services'],['application','Applications'],['web resource','Web endpoints']])select.append(new Option(title,value));kind.append(select);toolbar.append(search,kind,button('Explore network map',()=>operatorOpen({view:'map'})));discovery.append(toolbar);
  const workspace=el('div','','discovery-workspace');const targets=el('article','','card');targets.id='discovery-targets';const selection=el('article','','card');selection.id='discovery-selection';workspace.append(targets,selection);discovery.append(workspace);const jobs=el('article','','card');jobs.append(el('h2','Recent runs and coverage'));const jobList=el('div');jobList.id='operator-jobs';jobs.append(jobList);discovery.append(jobs);main.append(discovery);
  const tools=el('section');tools.id='tools';tools.className='view';tools.hidden=true;tools.append(el('p','FIND A TOOL BY ITS PURPOSE','eyebrow'),el('h1','Tools'),el('p','Discovery, testing and assessment tools in one place. Search a task or familiar tool name.'));const toolLabel=el('label','Find a tool');const toolSearch=el('input');toolSearch.id='tools-search';toolSearch.type='search';toolSearch.placeholder='Discovery, Repeater, CVE, authentication…';toolLabel.append(toolSearch);const count=el('p','','subline');count.id='tools-count';const list=el('div','','tools-grid');list.id='tools-list';tools.append(toolLabel,count,list);main.append(tools);
  const nav=document.querySelector('nav');const more=el('details');more.id='extra-views';more.append(el('summary','More workspace views'));nav.append(more);
  const finder=button('Find a tool',()=>{operatorToolsView($('tool-dialog-results'),'',true);$('tool-dialog-search').value='';$('tool-dialog').returnValue='';$('tool-dialog').showModal();$('tool-dialog-search').focus();});finder.id='tool-finder';finder.setAttribute('aria-keyshortcuts','Control+K Meta+K');document.querySelector('header').insertBefore(finder,document.querySelector('.local-badge'));
  const dialog=el('dialog');dialog.id='tool-dialog';const dialogHead=el('div','','dialog-heading');dialogHead.append(el('h2','Find a tool'),button('Close tool finder',()=>dialog.close()));const dialogLabel=el('label','Search tools');const dialogInput=el('input');dialogInput.id='tool-dialog-search';dialogInput.type='search';dialogLabel.append(dialogInput);const results=el('div');results.id='tool-dialog-results';dialog.append(dialogHead,dialogLabel,el('p','Search a task or tool. Escape closes this panel.','muted'),results);document.body.append(dialog);
  const flow=el('article','','card workflow-strip');flow.id='operator-workflow';flow.append(el('h2','Move the assessment forward'));for(const [text,view] of [['1 · Discover targets','discovery'],['2 · Choose a tool','tools'],['3 · Review findings','findings'],['4 · Report evidence','report']])flow.append(button(text,()=>operatorOpen({view})));$('overview').insertBefore(flow,$('summary'));
  dialog.addEventListener('close',()=>{if(dialog.returnValue!=='navigate')finder.focus();});
  dialog.addEventListener('keydown',e=>{if(e.key==='Escape'){e.preventDefault();dialog.close('');}},true);
  const evidenceActions=el('div','','button-row');evidenceActions.append(button('Open assessment activity',()=>operatorOpen({view:'activity'})),button('Import more evidence',()=>operatorOpen({view:'import'})));$('evidence').insertBefore(evidenceActions,$('evidence-search').closest('label'));
  input.addEventListener('input',operatorDiscoveryView);select.addEventListener('change',operatorDiscoveryView);toolSearch.addEventListener('input',()=>operatorToolsView(list,toolSearch.value));dialogInput.addEventListener('input',()=>operatorToolsView(results,dialogInput.value,true));document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();finder.click();}});
  operatorInitialized=true;window.atlasOperatorRefresh();
});
