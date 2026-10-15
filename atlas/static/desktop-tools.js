'use strict';
let companionReport = '', companionWorkspace = '', companionGeneration = 0;
const appSettings = document.createElement('section');
appSettings.id = 'appsettings'; appSettings.className = 'view'; appSettings.hidden = true;
appSettings.innerHTML = `<div class="page-heading"><div><p class="eyebrow">LOCAL EXECUTION · OPTIONAL COMPUTATION</p><h1>App & server</h1><p id="app-execution-position">Install Atlas on the machine running your lab VPN. Target tools use that machine's reviewed network routes.</p></div></div>
<div class="two-col"><article class="card"><h2>Computation companion</h2><p>Optional. Share selected software identities for cached advisory matching. Your targets, asset IDs, evidence, credentials for tested applications and complete assessments stay local.</p><p id="companion-status" role="status">Disconnected</p>
<form id="companion-connect"><label>Server HTTPS address<input id="companion-origin" type="url" placeholder="https://atlas.example.test" required maxlength="250"></label><label>Server operator password<input id="companion-password" type="password" autocomplete="off" required maxlength="200"></label><label>Private server public CA certificate (optional)<textarea id="companion-ca" maxlength="65536" placeholder="PEM public certificate only; verified TLS is required"></textarea></label><div class="button-row"><button class="primary">Connect to server</button><button type="button" id="companion-disconnect">Disconnect</button></div></form><p class="muted">Sign-in and connection settings stay in process memory. Reconnect after restarting. The server never runs target operations for the desktop client.</p></article>
<article class="card"><h2>Application updates</h2><p>Check the Atlas repository for a stable release. No background updates or downloaded code execute here.</p><button type="button" id="app-update-check">Check for updates</button><p id="app-update-status" role="status">No update check has been made.</p><div id="app-update-link"></div><p class="muted">Stop Atlas and back up its local data folder before installing an update. Updates keep the assessment data separate from the application.</p></article></div>
<article class="card"><h2>Review software for server analysis</h2><p>Select an assessment identity, then review an exact JSON list of CPE or package identities. Package names can disclose private software: include only what you intend to share. The server uses its loaded public advisory cache; no match is not a clean bill of health.</p>
<form id="companion-analyze"><label>Local assessment identity<select id="companion-subject"><option value="">Choose an identity</option></select></label><button type="button" id="companion-candidates">Prepare fingerprint identities for review</button><label>Software identities to share<textarea id="companion-inventory" rows="7" maxlength="32000" placeholder='[{"kind":"package","ecosystem":"PyPI","name":"example-package","version":"1.0.0"}]'>[]</textarea></label><label class="check"><input id="companion-allow" type="checkbox">I reviewed this list and allow sharing these software identities with the connected server.</label><button class="primary">Analyze selected software on server</button></form><pre id="companion-result" class="export-preview"></pre><div class="button-row"><button type="button" id="companion-save" disabled>Retain analysis as evidence</button><button type="button" id="companion-finding" disabled>Prepare finding from retained analysis</button></div><p class="muted">Retained analysis is inferred advisory evidence. A finding draft still needs your applicability and impact review.</p></article>`;
document.querySelector('main').append(appSettings);
let companionObservation = '';
function resetCompanionReport() {
  companionGeneration++;
  companionReport = ''; companionObservation = '';
  $('companion-result').textContent = '';
  $('companion-save').disabled = true; $('companion-finding').disabled = true;
  $('companion-allow').checked = false;
}
window.atlasDesktopRefresh = () => {
  const selected = $('companion-subject').value;
  options('companion-subject', state?.entities || [], 'Choose an identity');
  if (companionWorkspace === (state?.id || '')) {
    if (state?.entities.some(entity => entity.id === selected)) $('companion-subject').value = selected;
    return;
  }
  companionWorkspace = state?.id || ''; resetCompanionReport();
  $('companion-inventory').value = '[]';
};
async function refreshCompanionStatus() {
  const result = await api('companion/status');
  $('companion-status').textContent = result.connected ? 'Connected to ' + result.origin : 'Disconnected · local tools remain available';
  for (const input of appSettings.querySelectorAll('input,textarea,select,button')) input.disabled = !result.client_available;
  $('companion-save').disabled = !companionReport || !result.client_available;
  $('companion-finding').disabled = !companionObservation || !result.client_available;
  if (!result.client_available) {
    $('app-execution-position').textContent = 'This is a hosted Atlas session. Install the desktop app on your VPN host for local target execution. Companion connection settings are available in that installed app.';
  }
}
$('companion-connect').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    const password = $('companion-password').value; $('companion-password').value = '';
    await api('companion/connect', {origin: $('companion-origin').value, password, ca_pem: $('companion-ca').value});
    resetCompanionReport(); await refreshCompanionStatus();
  }, event.submitter);
});
$('companion-disconnect').addEventListener('click', () => run(async () => {
  await api('companion/disconnect', {}); resetCompanionReport(); await refreshCompanionStatus();
}));
for (const id of ['companion-subject','companion-inventory']) $(id).addEventListener('input', resetCompanionReport);
$('companion-candidates').addEventListener('click', () => run(async () => {
  needsWorkspace(); resetCompanionReport();
  const data = await api('vulnerability/status?workspace=' + encodeURIComponent(state.id));
  const rows = data.inventory_candidates.filter(row => row.subject === $('companion-subject').value && row.kind === 'cpe').slice(0,20);
  $('companion-inventory').value = JSON.stringify(rows.map(row => ({kind: 'cpe', cpe: row.cpe})), null, 2);
  if (!rows.length) message('No exact CPE fingerprint for that identity. Supply reviewed package/CPE identities manually.');
}));
$('companion-analyze').addEventListener('submit', event => {
  event.preventDefault(); run(async () => {
    needsWorkspace(); const workspace = state.id, generation = companionGeneration;
    const result = await api('companion/run', {workspace, subject: $('companion-subject').value,
      inventory: JSON.parse($('companion-inventory').value), allow_share: $('companion-allow').checked});
    if (workspace !== state?.id || generation !== companionGeneration) return;
    companionReport = result.report_id; companionObservation = '';
    $('companion-result').textContent = JSON.stringify(result.report, null, 2);
    $('companion-save').disabled = false; $('companion-finding').disabled = true;
  }, event.submitter);
});
$('companion-save').addEventListener('click', () => run(async () => {
  needsWorkspace(); const workspace = state.id;
  const saved = await api('companion/save', {workspace, report_id: companionReport});
  if (workspace !== state?.id) return;
  companionReport = ''; state = saved.workspace; companionObservation = saved.observation_id; render();
  $('companion-save').disabled = true; $('companion-finding').disabled = false;
  message('Advisory analysis retained as inferred evidence. Review applicability before documenting a finding.');
}));
$('companion-finding').addEventListener('click', () => run(async () => {
  needsWorkspace(); requireEmptyRecordDraft();
  const evidence = state.observations.find(row => row.id === companionObservation);
  if (!evidence) throw new Error('Retain the analysis in this workspace first.');
  show('activity'); $('record-kind').value = 'finding'; $('record-subject').value = evidence.subject;
  $('record-title').value = 'Review advisory applicability';
  $('record-details').value = 'Companion advisory correlation is an unvalidated lead. Document product identity, patches/backports, prerequisites and demonstrated impact before validation.';
  $('record-evidence').value = companionObservation; rememberRecordDraft(); $('record-title').focus();
}));
$('app-update-check').addEventListener('click', () => run(async () => {
  const result = await api('updates/check', {});
  $('app-update-status').textContent = result.newer ? 'Available: ' + result.available + ' · installed: ' + result.installed : 'Installed ' + result.installed + ' · latest stable release ' + result.available;
  $('app-update-link').replaceChildren(el('p', result.url), button('Open verified release page', () => api('updates/open', {})));
}, $('app-update-check')));
run(refreshCompanionStatus);
