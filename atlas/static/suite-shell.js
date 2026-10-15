/* Workflow apps share the same assessment. Switching apps is navigation only. */
'use strict';
(() => {
  const apps = [
    {id:'web',name:'Web & API',mark:'W',description:'Investigate applications, requests and authenticated access.',defaultView:'overview',views:[['overview','Start here'],['investigations','Investigations'],['discovery','Targets & discovery'],['web','Web workbench'],['console','Terminal & browser']],more:[['tools','All tools'],['vulnerability','Software advisories'],['appsettings','App & server']]},
    {id:'evidence',name:'Evidence',mark:'E',description:'Inspect shared observations, sources and relationships.',defaultView:'evidence',views:[['evidence','Evidence library'],['import','Import results'],['map','Relationships'],['activity','Notes & activity']],more:[]},
    {id:'delivery',name:'Reporting & Retest',mark:'R',description:'Review findings, compare retests and prepare the assessment report.',defaultView:'findings',views:[['findings','Finding review'],['retests','Retests'],['report','Reports & exports']],more:[]}
  ];
  const viewOwner = new Map(apps.flatMap(app => [...app.views,...app.more].map(([view]) => [view,app.id])));
  const viewNames = new Map(apps.flatMap(app => [...app.views,...app.more]));
  // No target, credential, draft or selected app is written to browser storage.
  const visits = new Map();
  let active = 'web', navigating = false;
  const currentApp = () => apps.find(app => app.id === active);
  const memory = () => { const key=state?.id || ''; if(!visits.has(key))visits.set(key,{});return visits.get(key); };

  function arrange() {
    if(navigating)return;
    navigating=true;
    try {
      const nav=document.querySelector('aside nav'),app=currentApp();
      if(!nav || !app)return;
      const all=new Map();
      // Async tool modules may append their own navigation after a placeholder
      // exists. Keep the module node and its handler, removing the older entry.
      for(const node of document.querySelector('aside').querySelectorAll('[data-view]')){
        const previous=all.get(node.dataset.view);
        if(previous){if(previous.dataset.suitePlaceholder==='true'){previous.remove();all.set(node.dataset.view,node);}else node.remove();}
        else all.set(node.dataset.view,node);
      }
      for(const [view,title] of [...app.views,...app.more]) {
        if(!all.has(view)) {
          const entry=button(title,()=>show(view));entry.dataset.view=view;entry.dataset.suitePlaceholder='true';all.set(view,entry);
        }
      }
      // Existing nodes retain their event handlers. Hidden destinations remain
      // available to explicit contextual handoffs and the suite-wide tool finder.
      const parked=$('suite-other-views');
      for(const [view,entry] of all){
        const own=viewOwner.get(view)===active;
        entry.textContent=viewNames.get(view)||entry.textContent;
        if(!own && entry.parentElement!==parked)parked.append(entry);
        entry.classList.toggle('selected',view===currentView);
        if(view===currentView)entry.setAttribute('aria-current','page');else entry.removeAttribute('aria-current');
      }
      const more=$('extra-views');
      app.views.forEach(([view],index)=>{const entry=all.get(view),position=nav.children[index];if(position!==entry)nav.insertBefore(entry,position||more);});
      for(const [view] of app.more){const entry=all.get(view);if(entry.parentElement!==more)more.append(entry);}
      more.hidden=!app.more.length;
      more.querySelector('summary').textContent='More in '+app.name;
      if(app.more.some(([view])=>view===currentView))more.open=true;
      nav.setAttribute('aria-label',app.name+' views');
      $('suite-nav-label').textContent=app.name;
      $('suite-current-app').textContent=app.name;
      $('suite-app-title').textContent=app.name;
      $('suite-app-purpose').textContent=app.description;
      document.body.dataset.suiteApp=active;
      for(const entry of $('suite-app-list').querySelectorAll('[data-suite-app]')) {
        const selected=entry.dataset.suiteApp===active;
        entry.setAttribute('aria-pressed',String(selected));
        entry.querySelector('.suite-app-state').textContent=selected?'Current app':'Open app';
      }
    } finally { navigating=false; }
  }
  function context() {
    $('suite-assessment').textContent=state?.name || 'Choose or create an assessment';
    $('suite-context-count').textContent=state ? state.observations.length+' observations · '+(state.findings.length+state.records.filter(record=>record.kind==='finding').length)+' findings' : 'One assessment shared across apps';
    $('suite-location').textContent=viewNames.get(currentView)||'Assessment';
    $('suite-context-scope').textContent=state?.scope || 'Testing uses the execution host and its reviewed route. Selecting an app never starts a test.';
    const activeJobs=(state?.web_runs||[]).filter(job=>['queued','running'].includes(job.state));
    const status=$('suite-running');status.hidden=!activeJobs.length;status.textContent=activeJobs.length+' running test'+(activeJobs.length===1?'':'s');
    document.title=currentApp().name+' · '+(state?.name ? state.name+' · ' : '')+'Atlas';
  }
  function selectApp(id) {
    const app=apps.find(item=>item.id===id);if(!app)return;
    const previous=active;
    memory()[active]=currentView;
    active=app.id;
    // Do not call operatorOpen here: preparing a tool is a distinct action.
    const saved=memory()[active],view=viewOwner.get(saved)===active?saved:app.defaultView;
    show(view);
    $('suite-switch-status').textContent=app.name+' opened. '+(state?.name || 'No assessment selected')+'.';
    if(previous!==active)$(view)?.querySelector('h1')?.focus({preventScroll:true});
  }
  function beforeShow(view) {
    const owner=viewOwner.get(view);if(!owner)return;
    if(viewOwner.get(currentView)===active)memory()[active]=currentView;
    active=owner;memory()[active]=view;arrange();
  }
  function afterShow() {
    arrange();context();
    const heading=$(currentView)?.querySelector('h1');if(heading)heading.tabIndex=-1;
  }
  function refresh() {
    // Workspaces remain the existing source of truth. Changing assessment resets
    // app-return destinations, while existing per-assessment draft guards apply.
    arrange();context();
  }
  function openSelector(){
    const dialog=$('suite-selector');if(dialog.open)return;
    $('suite-launcher').setAttribute('aria-expanded','true');dialog.showModal();
    dialog.querySelector('[data-suite-app="'+active+'"]')?.focus();
  }
  function init() {
    const header=document.querySelector('header'),aside=document.querySelector('aside');
    const launcher=button('',openSelector);launcher.id='suite-launcher';launcher.setAttribute('aria-label','Choose an Atlas app');launcher.setAttribute('aria-haspopup','dialog');launcher.setAttribute('aria-controls','suite-selector');launcher.setAttribute('aria-expanded','false');launcher.setAttribute('aria-keyshortcuts','Control+Shift+L Meta+Shift+L');
    const grid=el('span','','suite-launcher-grid');grid.setAttribute('aria-hidden','true');for(let i=0;i<9;i++)grid.append(el('i'));
    const name=el('span','Web & API');name.id='suite-current-app';launcher.append(grid,name,el('span','⌄','suite-caret'));header.prepend(launcher);
    const brand=header.querySelector('.brand');brand.innerHTML='';brand.append(el('span','Atlas'));brand.removeAttribute('href');brand.setAttribute('aria-label','Assessment Atlas');
    $('workspace').previousElementSibling.textContent='Assessment';
    const navTitle=el('p','Web & API','suite-nav-label');navTitle.id='suite-nav-label';aside.prepend(navTitle);
    const parked=el('div');parked.id='suite-other-views';parked.hidden=true;aside.append(parked);
    const dialog=el('dialog');dialog.id='suite-selector';dialog.setAttribute('aria-labelledby','suite-selector-title');
    const head=el('div','','dialog-heading'),title=el('h2','Atlas apps');title.id='suite-selector-title';head.append(title,button('Close',()=>dialog.close('')));dialog.append(head,el('p','Choose a workflow. Your selected assessment, evidence and findings stay together.','muted'));
    const list=el('div','','suite-app-grid');list.id='suite-app-list';
    for(const app of apps){
      const choice=button('',()=>{dialog.close('navigate');selectApp(app.id);},'suite-app-choice');choice.dataset.suiteApp=app.id;
      const mark=el('span',app.mark,'suite-app-mark');mark.setAttribute('aria-hidden','true');
      choice.append(mark,el('strong',app.name),el('span',app.description,'suite-app-description'),el('span','Open app','suite-app-state'));list.append(choice);
    }
    dialog.append(list,el('p','Ctrl/Command + Shift + L opens this selector. Ctrl/Command + K finds any tool.','subline'));document.body.append(dialog);
    const live=el('p','','suite-sr-only');live.id='suite-switch-status';live.setAttribute('role','status');document.body.append(live);
    dialog.addEventListener('close',()=>{launcher.setAttribute('aria-expanded','false');if(dialog.returnValue!=='navigate')launcher.focus();});
    dialog.addEventListener('keydown',event=>{
      const buttons=[...list.querySelectorAll('button')],index=buttons.indexOf(document.activeElement);
      if(event.key==='Escape'){event.preventDefault();dialog.close('');}
      else if(['ArrowRight','ArrowDown','ArrowLeft','ArrowUp'].includes(event.key)&&index>=0){event.preventDefault();const next=index+(['ArrowRight','ArrowDown'].includes(event.key)?1:-1);buttons[(next+buttons.length)%buttons.length].focus();}
    });
    document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.shiftKey&&event.key.toLowerCase()==='l'&&!event.target.closest?.('#terminal-screen,#embedded-screen')){event.preventDefault();openSelector();}});
    const contextBar=el('section','','suite-context');contextBar.setAttribute('aria-label','Shared assessment context');
    const contextLine=el('div','','suite-context-line');const assessment=el('strong');assessment.id='suite-assessment';const count=el('span');count.id='suite-context-count';const running=el('span','','badge');running.id='suite-running';running.hidden=true;contextLine.append(assessment,count,running);
    const scope=el('p','','suite-context-scope');scope.id='suite-context-scope';contextBar.append(contextLine,scope);
    const appLine=el('div','','suite-app-heading'),appText=el('div');const appTitle=el('p','','eyebrow');appTitle.id='suite-app-title';const purpose=el('p','','subline');purpose.id='suite-app-purpose';appText.append(appTitle,purpose);const location=el('span','','suite-location');location.id='suite-location';appLine.append(appText,location);
    const main=document.querySelector('main');main.prepend(contextBar,appLine);
    // Start page is an actionable Web & API workflow; the shared evidence counts
    // remain below it rather than becoming three independent dashboards.
    const strip=$('operator-workflow');if(strip){strip.querySelector('h2').textContent='Investigate a web application';const actions=[['1 · Discover targets','discovery'],['2 · Continue an investigation','investigations'],['3 · Review shared evidence','evidence'],['4 · Review findings & retest','findings']];strip.querySelectorAll('button').forEach((entry,index)=>{const [text,view]=actions[index];entry.replaceWith(button(text,()=>show(view)));});}
    const overview=$('overview');overview.querySelector('.eyebrow').textContent='WEB & API · ASSESSMENT START';
    const welcome=$('welcome');welcome.querySelector('h2').textContent='Start with a target and a question.';welcome.querySelector('p').textContent='Bring in discoveries or scope a web test. Keep requests, authenticated sessions and the reasoning behind each finding in one assessment.';
    $('workspace-title').textContent=state?.name || 'Investigate, retain evidence, explain.';
    // Older modules add their navigation after asynchronous HTML loads.
    const nav=document.querySelector('aside nav');
    if(!$('extra-views')){const more=el('details');more.id='extra-views';more.append(el('summary','More in Web & API'));nav.append(more);}
    const observer=new MutationObserver(records=>{if(records.some(record=>[...record.addedNodes].some(node=>node.nodeType===1&&node.matches?.('[data-view]'))))arrange();});
    observer.observe(nav,{childList:true,subtree:true});
    window.atlasSuiteArrange=arrange;window.atlasSuiteBeforeShow=beforeShow;window.atlasSuiteAfterShow=afterShow;window.atlasSuiteRefresh=refresh;
    // Testable navigation contract; accepting fixed app IDs cannot execute tools.
    window.atlasSuiteSelectApp=selectApp;
    beforeShow(currentView);afterShow();
  }
  init();
})();
