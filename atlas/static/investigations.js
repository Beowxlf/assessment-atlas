'use strict';
// Drafts live in their workspace on the server only after an explicit first save.
// In-memory edits remain separate from polled workspace views and session secrets.
(() => {
  const fields = ['question','objective','subject','status','decision','rationale','next_action','access_mode','access_role','access_reference'];
  const editors = new Map();
  let ready = false, visibleWorkspace = '', filling = false, executionStatus = null, executionWorkspace = '', executionPending = null;

  function blank() {
    return {question:'',objective:'',subject:'',status:'open',decision:'undecided',rationale:'',next_action:'',access_mode:'anonymous',access_role:'',access_reference:'',execution_context:null};
  }
  function values(item) { return {...Object.fromEntries(fields.map(key => [key, item?.[key] ?? blank()[key]])),execution_context:item?.execution_context?{...item.execution_context}:null}; }
  function current() { return state?.id ? editors.get(state.id) : null; }
  function items() { return state?.investigations || []; }
  function persisted(ctx) { return items().find(item => item.id === ctx?.id); }
  function context(workspace, item = null) {
    return {workspace,id:item?.id || '',revision:item?.revision || 0,values:values(item),dirty:false,edit:0,pending:null,mutating:false,mutationDone:null,finishMutation:null,timer:null,error:'',savedAt:item?.updated_at || '',findingTitle:'',findingDetails:'',nextQuestion:'',evidenceSelection:new Set(),selectionInitialized:false};
  }
  function isCurrent(ctx) { return state?.id === ctx.workspace && current() === ctx; }
  function heading() {
    const ctx=current(); if (!ctx || !ready) return;
    $('investigation-heading').textContent=ctx.values.question || 'Start with a question';
    const status=$('investigation-save-state');
    status.textContent=ctx.pending ? 'Saving…' : ctx.error ? 'Update failed · '+ctx.error : ctx.dirty ? 'Unsaved changes' : ctx.id ? 'Saved draft'+(ctx.savedAt?' · '+ctx.savedAt:'') : 'Unsaved draft';
    status.className=ctx.error ? 'investigation-save-error' : ctx.dirty ? 'investigation-unsaved' : '';
    $('investigation-save').disabled=!!ctx.pending;
    $('investigation-save').textContent=ctx.pending ? 'Saving…' : 'Save draft';
    $('investigation-compare-saved').hidden=!ctx.id || !ctx.error;
    $('investigation-reload-saved').hidden=!ctx.id || !ctx.error;
    $('investigation-access-fields').hidden=ctx.values.access_mode!=='authenticated';
    $('investigation-access_reference').required=ctx.values.access_mode==='authenticated';
    $('investigation-access_role').required=ctx.values.access_mode==='authenticated';
    $('investigation-context-note').textContent=ctx.values.access_mode==='authenticated'
      ? 'Authentication must be re-established in the workbench. Saved role/reference labels never restore a session or prove access.'
      : 'Saved context is a plan. Review execution host, scope and authorization in the testing controls.';
    $('investigation-prepare').textContent=ctx.values.access_mode==='authenticated' ? 'Prepare an authenticated test' : 'Prepare a web test';
  }
  function readForm(includeExecution=false) {
    const data=Object.fromEntries(fields.map(key => [key,$('investigation-'+key).value]));
    if (data.access_mode==='anonymous') { data.access_role=''; data.access_reference=''; }
    const host_id=$('investigation-execution-host').value,expected=$('investigation-interface').value;
    data.execution_context=(includeExecution||current()?.values.execution_context)&&host_id&&expected?{host_id,interface:expected}:null;
    return data;
  }
  function executionFields(){
    const ctx=current();if(!ctx||!ready)return;const selected=ctx.values.execution_context;
    const hosts=clear('investigation-execution-host');hosts.append(new Option('Choose current execution server',''));
    if(executionStatus)hosts.append(new Option(executionStatus.host.name+' · '+executionStatus.host.platform+' · server',executionStatus.host.id));
    if(selected?.host_id&&!([...hosts.options].some(option=>option.value===selected.host_id)))hosts.append(new Option('Previously selected host · unavailable here',selected.host_id));
    hosts.value=selected?.host_id||'';
    const interfaces=$('investigation-interface');
    if(executionStatus&&window.atlasExecutionInterfaceOptions)window.atlasExecutionInterfaceOptions(interfaces,executionStatus,selected?.interface||executionStatus.default_interface);
    else {interfaces.replaceChildren(new Option(selected?.interface||'Choose expected interface',selected?.interface||''));}
    // Defaults are a proposed choice only. The next explicit save records them.
    if(!selected&&executionStatus){hosts.value=executionStatus.host.id;interfaces.value=executionStatus.default_interface||'system';}
    $('investigation-execution-note').textContent=selected?.host_id&&executionStatus&&selected.host_id!==executionStatus.host.id?'The saved host is unavailable on this server. Select and save the current host/interface before testing.':!selected?'Execution context has not been saved. The displayed default is a proposal; Save draft records it. Historical tests without context remain unknown.':'Expected '+selected.interface+' on the execution server. The viewing computer supplies no VPN route. System routing does not prove VPN health; readiness is checked again in the workbench.';
  }
  function loadExecution(){
    if(!state||!window.atlasExecutionStatus)return;const workspace=state.id;
    if(executionWorkspace===workspace&&executionStatus)return;if(executionPending===workspace)return;
    executionPending=workspace;
    window.atlasExecutionStatus().then(result=>{if(state?.id!==workspace)return;executionStatus=result;executionWorkspace=workspace;executionFields();}).catch(error=>{if(state?.id===workspace)$('investigation-execution-note').textContent='Execution host could not be described: '+error.message;}).finally(()=>{if(executionPending===workspace)executionPending=null;});
  }
  function changed(event) {
    if (filling) return;
    const ctx=current(); if (!ctx) return;
    ctx.values=readForm(['investigation-execution-host','investigation-interface'].includes(event?.target?.id)); ctx.edit++; ctx.dirty=true; ctx.error='';
    clearTimeout(ctx.timer); heading();
    if (ctx.id && ctx.values.question.trim() && $('investigation-form').checkValidity()) {
      ctx.timer=setTimeout(() => { save(ctx).catch(() => {}); },1400);
    }
  }
  function selectedItem(ctx, result) {
    const id=result.investigation_result_id || ctx.id;
    if (id) return (result.investigations || []).find(item => item.id===id);
    // Compatibility fallback for older response-only metadata; never select an ambiguous match.
    const matches=(result.investigations || []).filter(item => item.question===ctx.values.question && item.subject===ctx.values.subject);
    if (matches.length!==1) throw new Error('Draft was saved, but its identity could not be selected. Refresh the investigation list.');
    return matches[0];
  }
  async function save(ctx,explicit=false) {
    clearTimeout(ctx.timer);
    if (ctx.mutating) { await ctx.mutationDone; return save(ctx,explicit); }
    if (ctx.pending) { await ctx.pending; return save(ctx,explicit); }
    if(explicit&&isCurrent(ctx)&&!ctx.values.execution_context){const candidate=readForm(true).execution_context;if(candidate){ctx.values.execution_context=candidate;ctx.edit++;ctx.dirty=true;}}
    if (!ctx.dirty && ctx.id) return ctx;
    if (!ctx.values.question.trim()) { ctx.error='Enter the question before saving.'; if(isCurrent(ctx)) heading(); throw new Error(ctx.error); }
    if (isCurrent(ctx) && !$('investigation-form').reportValidity()) throw new Error('Review the highlighted investigation fields.');
    const snapshot={...ctx.values},version=ctx.edit;
    const request={workspace:ctx.workspace,...snapshot};
    if (ctx.id) Object.assign(request,{id:ctx.id,revision:ctx.revision});
    ctx.error='';
    ctx.pending=(async () => {
      try {
        const result=await api('investigation/save',request);
        const item=selectedItem(ctx,result);
        if (!item) throw new Error('Saved draft was not present in the response. Refresh before continuing.');
        ctx.id=item.id; ctx.revision=item.revision; ctx.savedAt=item.updated_at || '';
        ctx.dirty=ctx.edit!==version;
        if (!ctx.dirty) ctx.values=values(item);
        if (isCurrent(ctx)) { state=result; render(); }
      } catch(error) {
        ctx.error=error.message; ctx.dirty=true;
        if(isCurrent(ctx)) message('Investigation not saved: '+error.message,true);
        throw error;
      } finally { ctx.pending=null; if(isCurrent(ctx)) heading(); }
      return ctx;
    })();
    if(isCurrent(ctx)) heading();
    return ctx.pending;
  }
  async function flush(ctx) {
    if (!ctx) throw new Error('Choose a workspace first.');
    await save(ctx,true);
    // An edit made during a pending save must be persisted before a handoff.
    if (ctx.dirty) await save(ctx,true);
    if (ctx.dirty || ctx.error) throw new Error('Save the current edits before continuing.');
    if (!isCurrent(ctx)) throw new Error('The workspace changed. Return to this investigation to continue.');
  }
  async function mutate(path, extra) {
    const ctx=current(); await flush(ctx);
    if(ctx.mutating)throw new Error('An investigation update is already in progress.');
    ctx.mutating=true;
    ctx.mutationDone=new Promise(resolve => { ctx.finishMutation=resolve; });
    try {
      const result=await api('investigation/'+path,{workspace:ctx.workspace,id:ctx.id,revision:ctx.revision,...extra});
      const saved=(result.investigations || []).find(item => item.id===ctx.id);
      if (saved) { ctx.revision=saved.revision; ctx.savedAt=saved.updated_at || ''; }
      if (isCurrent(ctx)) { state=result; render(); }
      return {ctx,result};
    } catch(error) {
      ctx.error=error.message;
      if(isCurrent(ctx))heading();
      throw error;
    } finally { ctx.mutating=false; ctx.finishMutation(); ctx.mutationDone=null; ctx.finishMutation=null; }
  }
  async function prepareTest(ctx,resume_preparation=null){
    await flush(ctx);
    if(!ctx.values.execution_context)throw new Error('Choose and save an execution host and expected interface first.');
    if(!window.atlasPrepareInvestigationTest)throw new Error('Testing controls are still loading. Try again in a moment.');
    await window.atlasPrepareInvestigationTest({workspace:ctx.workspace,investigation_id:ctx.id,revision:ctx.revision,access_mode:ctx.values.access_mode,access_role:ctx.values.access_role,access_reference:ctx.values.access_reference,subject:ctx.values.subject,execution_context:{...ctx.values.execution_context},...(resume_preparation?{resume_preparation}:{})});
  }
  async function prepareResume(run_id){
    const ctx=current();await flush(ctx);const revision=ctx.revision;
    try{
      const result=await api('investigation/resume',{workspace:ctx.workspace,id:ctx.id,revision,run_id});
      if(!isCurrent(ctx)||ctx.dirty||ctx.pending||ctx.revision!==revision)throw new Error('The investigation changed during resume preparation. Save current work and prepare again.');
      if(!result.resume_preparation)throw new Error('No safe resume configuration is available. Prepare a fresh test and inspect the original result.');
      await prepareTest(ctx,result.resume_preparation);
    }catch(error){ctx.error=error.message;if(isCurrent(ctx))heading();throw error;}
  }
  function choose(item) {
    const ctx=context(state.id,item); editors.set(state.id,ctx); fill(); refreshPanels(); renderList();
  }
  async function open(id) {
    const ctx=current();
    if (ctx?.dirty || ctx?.pending) await flush(ctx);
    const item=items().find(entry => entry.id===id); if (!item) throw new Error('The saved investigation is no longer available. Refresh the workspace.');
    choose(item); show('investigations'); $('investigation-question').focus({preventScroll:true});
  }
  function fill() {
    const ctx=current(); if (!ctx || !ready) return;
    filling=true;
    const selected=ctx.values.subject;
    clear('investigation-subject').append(new Option('Entire engagement',''));
    for(const entity of state.entities || []) $('investigation-subject').append(new Option(entity.label+' · '+entity.kind+' · '+entity.id.slice(0,8),entity.id));
    if(selected && ![...$('investigation-subject').options].some(option => option.value===selected)) $('investigation-subject').append(new Option('Unavailable identity · '+selected,selected));
    for(const key of fields) $('investigation-'+key).value=ctx.values[key];
    executionFields();
    $('investigation-finding-title').value=ctx.findingTitle;
    $('investigation-finding-details').value=ctx.findingDetails;
    $('investigation-next-question').value=ctx.nextQuestion;
    filling=false; heading();
  }
  function renderList() {
    if (!ready) return;
    const query=$('investigation-search').value.toLowerCase().trim(); clear('investigation-list');
    const rows=items().filter(item => !query || [item.question,item.objective,item.next_action,label(item.subject)].join(' ').toLowerCase().includes(query));
    for(const item of [...rows].sort((a,b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')))) {
      const row=el('div','','investigation-list-item');
      const pick=button(item.question,() => open(item.id)); pick.dataset.investigation=item.id; pick.setAttribute('aria-pressed',String(current()?.id===item.id));
      row.append(pick,el('p',item.status+' · '+item.decision,'subline'));
      if(item.next_action) row.append(el('p',item.next_action,'subline'));
      $('investigation-list').append(row);
    }
    if(!rows.length) $('investigation-list').append(el('p',query?'No matching investigations.':'No saved investigations yet. Ask one question to start.','muted'));
    const ctx=current();
    if (ctx && !ctx.id && ctx.dirty) $('investigation-list').prepend(el('p','New question · unsaved in this tab','subline'));
  }
  function linkEvidence(item) { return item?.evidence_refs || []; }
  function linkRuns(item) { return item?.tests || []; }
  function observationID(link) { return typeof link==='string' ? link : link.observation_id || link.id; }
  function runID(link) { return typeof link==='string' ? link : link.run_id || link.id; }
  function refreshPanels() {
    const ctx=current(),item=persisted(ctx); if (!ctx || !ready) return;
    const savedRun=$('investigation-run').value, savedObservation=$('investigation-observation').value;
    clear('investigation-run').append(new Option('Choose a retained run',''));
    for(const test of state.web_runs || []) $('investigation-run').append(new Option(test.kind+' · '+test.state+' · '+test.id.slice(0,8),test.id));
    if ([...$('investigation-run').options].some(option => option.value===savedRun)) $('investigation-run').value=savedRun;
    clear('investigation-observation').append(new Option('Choose an observation',''));
    for(const observation of state.observations || []) $('investigation-observation').append(new Option(observation.kind+' · '+label(observation.subject)+' · '+observation.status+' · '+observation.id.slice(0,8),observation.id));
    if ([...$('investigation-observation').options].some(option => option.value===savedObservation)) $('investigation-observation').value=savedObservation;
    clear('investigation-linked-runs');
    const runs=linkRuns(item);
    for(const link of runs) {
      const original=(state.web_runs || []).find(test => test.id===runID(link));
      const row=el('div','','list-item'); row.append(el('h3',original?.kind || link.snapshot?.kind || 'Retained test snapshot'),badge(original?.state || link.snapshot?.state || 'unknown'),el('p',original?.reason || link.snapshot?.completeness || 'Inspect the preserved configuration and completeness before interpreting this test.','subline'),button('Inspect linked run',() => details('Investigation test',[link,original || {limit:'Original run unavailable; retained snapshot only.'}])));
      const snapshot=link.snapshot||{},execution=snapshot.execution_context||snapshot.context?.execution_context;
      row.append(el('p',execution?'Execution context: '+(execution.host?.name||execution.host_id||'unknown host')+' · '+(execution.interface||'unknown interface'):'Historical execution context unknown. A saved result does not prove current route or access.','subline'));
      if(['interrupted','cancelled','canceled','stopped','partial','failed'].includes(original?.state||snapshot.state)||['partial','incomplete'].includes(snapshot.completeness)){
        const resume=button('Prepare a new run from this result',()=>prepareResume(runID(link)));resume.dataset.resumeRun=runID(link);row.append(resume);
      }
      $('investigation-linked-runs').append(row);
    }
    if(!runs.length) $('investigation-linked-runs').append(el('p','No linked test yet. A failed or partial run does not establish a negative result.','muted'));
    clear('investigation-linked-evidence');
    const evidence=linkEvidence(item),ids=new Set(evidence.map(observationID));
    for(const selected of ctx.evidenceSelection) if(!ids.has(selected)) ctx.evidenceSelection.delete(selected);
    if(!ctx.selectionInitialized && evidence.length) { for(const id of ids) ctx.evidenceSelection.add(id); ctx.selectionInitialized=true; }
    for(const link of evidence) {
      const observation=(state.observations || []).find(entry => entry.id===observationID(link));
      const row=el('div','','list-item investigation-evidence-item');
      const check=el('input'); check.type='checkbox'; check.value=observationID(link); check.checked=ctx.evidenceSelection.has(check.value); check.addEventListener('change',() => { if(check.checked)ctx.evidenceSelection.add(check.value); else ctx.evidenceSelection.delete(check.value); });
      const pick=el('label','','check'); pick.append(check,document.createTextNode('Include in finding draft'));
      row.append(badge(link.relation || 'context'),el('strong',observation?.kind || 'Linked observation'),el('p',(observation?label(observation.subject)+' · '+observation.status+' · ': '')+observationID(link),'subline'),pick,button('Inspect linked evidence',() => observation ? observationDetails(observation) : details('Retained evidence reference',[link])));
      $('investigation-linked-evidence').append(row);
    }
    if(!evidence.length) $('investigation-linked-evidence').append(el('p','No linked observations yet. Support and contradiction remain separately inspectable.','muted'));
    clear('investigation-history');
    for(const entry of [...(item?.events || [])].reverse()) $('investigation-history').append(el('div',[entry.at,entry.action,entry.detail || entry.changed_fields?.join(', '),entry.decision,entry.status].filter(Boolean).join(' · '),'list-item'));
    if(!item?.events?.length) $('investigation-history').append(el('p','History begins with the first saved draft.','muted'));
    clear('investigation-next-links');
    for(const id of item?.next_investigation_ids || []) { const next=items().find(entry => entry.id===id); if(next)$('investigation-next-links').append(button('Continue: '+next.question,() => open(id))); }
    clear('investigation-finding-link');
    if(item?.finding_record_id) $('investigation-finding-link').append(el('p','A manual finding draft is linked. Creating another draft is disabled.','subline'),button('Open linked finding',async() => { await flush(current()); clearFindingFilters(); renderFindings(); show('findings'); const card=$('finding-'+item.finding_record_id); if(card){card.scrollIntoView({block:'center'});card.focus({preventScroll:true});} }));
    $('investigation-create-finding').disabled=!!item?.finding_record_id;
  }
  function continuation() {
    if(!ready) return;
    const host=clear('investigation-continuation'); host.hidden=!state;
    if(!state) return;
    host.append(el('p','PICK UP THE REASONING','eyebrow'),el('h2','Continue an investigation'));
    const openItems=items().filter(item => item.status!=='closed').sort((a,b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')));
    for(const item of openItems.slice(0,3)) {
      const row=el('div','','list-item'); row.append(badge(item.status),el('strong',item.question),el('p',item.rationale || 'No interpretation recorded yet.','subline'),el('p','Next: '+(item.next_action || 'Choose the smallest useful test.'),'subline'));
      if(item.access_mode==='authenticated')row.append(el('p','Authentication must be re-established before testing.','subline'));
      row.append(button('Resume investigation',() => open(item.id))); host.append(row);
    }
    if(!openItems.length) host.append(el('p',items().length?'No open investigations. Closed questions remain available with their evidence.':'Turn an observation into a question, test it and keep its reasoning here.','muted'));
    host.append(button('Open investigations',() => show('investigations')));
  }
  function refresh() {
    if(!ready) return;
    $('investigation-empty').hidden=!!state; $('investigation-workspace').hidden=!state; $('investigation-new').disabled=!state;
    if(!state) { visibleWorkspace=''; continuation(); clear('investigation-list'); return; }
    loadExecution();
    let ctx=current();
    if(!ctx) { const latest=[...items()].sort((a,b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')))[0]; ctx=context(state.id,latest); editors.set(state.id,ctx); }
    const changedWorkspace=visibleWorkspace!==state.id; visibleWorkspace=state.id;
    const item=persisted(ctx);
    if(item && !ctx.dirty && !ctx.pending && item.revision!==ctx.revision) { ctx.values=values(item); ctx.revision=item.revision; ctx.savedAt=item.updated_at || ''; fill(); }
    else if(changedWorkspace || !document.activeElement?.closest('#investigation-form')) fill();
    renderList(); refreshPanels(); continuation(); heading();
  }
  window.atlasInvestigationRefresh=refresh;
  window.atlasInvestigationShow=view => { if(view==='investigations') refresh(); };
  window.addEventListener('beforeunload',event => { if([...editors.values()].some(ctx => ctx.dirty || ctx.pending)) { event.preventDefault(); event.returnValue=''; } });

  run(async () => {
    const response=await fetch('/investigations.html'); if(!response.ok) throw new Error('Investigations could not load.');
    const wrapper=el('div'); wrapper.innerHTML=await response.text(); document.querySelector('main').append(wrapper.firstElementChild);
    const brief=el('article','','card investigation-continuation'); brief.id='investigation-continuation'; brief.hidden=true; $('overview').insertBefore(brief,$('summary'));
    $('investigation-form').addEventListener('input',changed);
    $('investigation-form').addEventListener('change',changed);
    $('investigation-form').addEventListener('submit',event => { event.preventDefault(); run(async() => { await flush(current()); message('Investigation draft saved in this assessment.'); }); });
    $('investigation-new').addEventListener('click',() => run(async() => { needsWorkspace(); const ctx=current(); if(ctx?.dirty || ctx?.pending) await flush(ctx); choose(null); $('investigation-question').focus(); }));
    $('investigation-search').addEventListener('input',renderList);
    $('investigation-compare-saved').addEventListener('click',() => run(async() => { const ctx=current(); const latest=await api('workspace?id='+encodeURIComponent(ctx.workspace)); if(!isCurrent(ctx))return; const item=(latest.investigations || []).find(entry => entry.id===ctx.id); details('Compare local edits with saved draft',[{local_unsaved_values:ctx.values},{saved_investigation:item || {limit:'Saved investigation unavailable'}}]); }));
    $('investigation-reload-saved').addEventListener('click',() => run(async() => { const ctx=current(); const latest=await api('workspace?id='+encodeURIComponent(ctx.workspace)); if(!isCurrent(ctx))return; const item=(latest.investigations || []).find(entry => entry.id===ctx.id); if(!item)throw new Error('The saved investigation is unavailable. Your local edits remain in this tab.'); clearTimeout(ctx.timer); state=latest; choose(item); render(); message('Saved draft reloaded. Local unsaved edits were discarded.'); }));
    $('investigation-prepare').addEventListener('click',() => run(async() => { await prepareTest(current()); },$('investigation-prepare')));
    $('investigation-refresh').addEventListener('click',() => run(async() => { const ctx=current(); await flush(ctx); await load(ctx.workspace); },$('investigation-refresh')));
    $('investigation-inspect-run').addEventListener('click',() => run(async() => { const test=(state?.web_runs || []).find(entry => entry.id===$('investigation-run').value); if(!test)throw new Error('Choose a retained run first.'); details('Reviewed test and completeness',[test]); }));
    $('investigation-link-run').addEventListener('click',() => run(async() => { const run_id=$('investigation-run').value; if(!run_id)throw new Error('Choose a retained run first.'); await mutate('run',{run_id}); message('Test linked with its retained configuration and outcome.'); },$('investigation-link-run')));
    $('investigation-inspect-observation').addEventListener('click',() => run(async() => { const observation=state?.observations.find(entry => entry.id===$('investigation-observation').value); if(!observation)throw new Error('Choose an observation first.'); observationDetails(observation); }));
    $('investigation-link-evidence').addEventListener('click',() => run(async() => { const observation_id=$('investigation-observation').value,relation=$('investigation-relation').value; if(!observation_id)throw new Error('Choose an observation first.'); const {ctx}=await mutate('evidence',{observation_id,relation}); ctx.evidenceSelection.add(observation_id); if(isCurrent(ctx))refreshPanels(); message('Evidence linked as '+relation+'. The source observation is unchanged.'); },$('investigation-link-evidence')));
    for(const [id,key] of [['investigation-finding-title','findingTitle'],['investigation-finding-details','findingDetails'],['investigation-next-question','nextQuestion']]) $(id).addEventListener('input',() => { const ctx=current(); if(ctx)ctx[key]=$(id).value; });
    $('investigation-create-finding').addEventListener('click',() => run(async() => { const ctx=current(); const title=$('investigation-finding-title').value.trim(),details=$('investigation-finding-details').value.trim(); if(!title || !details)throw new Error('Supply a finding title and observed behavior with its proof gaps.'); if(!ctx?.evidenceSelection.size)throw new Error('Select at least one linked observation for the finding draft.'); $('investigation-create-finding').disabled=true; try { await mutate('finding',{title,details,evidence_ids:[...ctx.evidenceSelection]}); message('Manual finding draft created with selected evidence references. Review its impact and proof gaps in Findings.'); } finally { if(isCurrent(ctx))$('investigation-create-finding').disabled=!!persisted(ctx)?.finding_record_id; } }));
    $('investigation-create-next').addEventListener('click',() => run(async() => { const question=$('investigation-next-question').value.trim(); if(!question)throw new Error('Enter the next question first.'); const {ctx,result}=await mutate('next',{question}); if(!isCurrent(ctx))return; const source=result.investigations.find(item => item.id===ctx.id); const id=result.investigation_result_id || source?.next_investigation_ids?.at(-1); const next=result.investigations.find(item => item.id===id); if(!next)throw new Error('Next question saved. Open it from the investigation list.'); ctx.nextQuestion=''; choose(next); $('investigation-question').focus(); message('Next question created. Existing evidence and decisions remain linked in the prior investigation.'); },$('investigation-create-next')));
    document.addEventListener('keydown',event => { if((event.ctrlKey || event.metaKey) && event.key.toLowerCase()==='s' && currentView==='investigations' && event.target.closest?.('#investigation-form')) { event.preventDefault(); if(!current()?.pending)$('investigation-form').requestSubmit(); } });
    ready=true; refresh();
  });
})();
