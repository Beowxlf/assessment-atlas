"""Versioned, inert investigation records over existing assessment evidence.

No function here starts collection or restores authentication. Run snapshots use a
small server-derived allowlist, never a caller-supplied request configuration.
"""
import copy
import datetime as dt
import re
import uuid
from urllib.parse import urlsplit, urlunsplit

from .importers import ImportProblem, clean

VERSION = 1
MAX_INVESTIGATIONS = 200
MAX_EVIDENCE = 200
MAX_TESTS = 100
MAX_EVENTS = 500
STATUSES = ('open', 'in progress', 'blocked', 'closed')
DECISIONS = ('undecided', 'supported', 'refuted', 'inconclusive')
RELATIONS = ('supporting', 'contradicting', 'context')
TEXT_LIMITS = {'question': 1000, 'objective': 4000, 'rationale': 8000,
               'next_action': 2000, 'access_role': 120, 'access_reference': 100}
EDITABLE = set(TEXT_LIMITS) | {'subject', 'status', 'decision', 'access_mode', 'evidence_refs', 'execution_context'}
PROOF_LIMITS = ('Operator-authored finding, not independently validated. Supporting, '
                'contradicting and contextual evidence retain their original claim levels. '
                'A completed run or supported decision does not establish exploitation, '
                'authorization failure or demonstrated impact.')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ensure(workspace):
    """Add only missing collection metadata; legacy IDs/content stay intact."""
    changed = False
    if 'investigations_version' not in workspace:
        workspace['investigations_version'] = VERSION
        changed = True
    if workspace['investigations_version'] != VERSION:
        raise ImportProblem('Unsupported investigation schema; preserve this workspace and use its compatible application version.')
    if 'investigations' not in workspace:
        workspace['investigations'] = []
        changed = True
    if not isinstance(workspace['investigations'], list):
        raise ImportProblem('Invalid investigation collection; preserve this workspace.')
    return changed


def request(data, fields):
    if not isinstance(data, dict) or set(data) - (set(fields) | {'workspace'}):
        raise ImportProblem('Unsupported investigation fields. Live credentials, configurations and session state cannot be saved here.')


def text(value, field, required=False):
    limit = TEXT_LIMITS.get(field, 8000)
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ImportProblem(f'{field.replace("_", " ").capitalize()} must contain {"1" if required else "0"}–{limit} characters.')
    return clean(value.strip())


def subject(workspace, value):
    if value is None or value == '':
        return None
    if not isinstance(value, str) or value not in {e['id'] for e in workspace['entities']}:
        raise ImportProblem('Investigation subject is outside this workspace.')
    return value


def evidence(workspace, values):
    if not isinstance(values, list) or len(values) > MAX_EVIDENCE:
        raise ImportProblem(f'Use at most {MAX_EVIDENCE} investigation evidence references.')
    known = {o['id'] for o in workspace['observations']}
    result, seen = [], set()
    for ref in values:
        if not isinstance(ref, dict) or set(ref) != {'observation_id', 'relation'}:
            raise ImportProblem('Evidence references require an observation ID and relation.')
        key, relation = ref['observation_id'], ref['relation']
        if not isinstance(key, str) or key not in known:
            raise ImportProblem('Evidence observation is outside this workspace.')
        if relation not in RELATIONS:
            raise ImportProblem('Choose supporting, contradicting or context evidence.')
        if key in seen:
            raise ImportProblem('An observation may have only one relation in an investigation.')
        seen.add(key)
        result.append({'observation_id': key, 'relation': relation})
    return result


def get(workspace, data, check_revision=True):
    ensure(workspace)
    item = next((i for i in workspace['investigations'] if i['id'] == data.get('id')), None)
    if not item:
        raise ImportProblem('Investigation not found in this workspace.')
    if check_revision:
        revision = data.get('revision')
        if isinstance(revision, bool) or not isinstance(revision, int) or revision != item['revision']:
            raise ImportProblem('Investigation changed. Refresh and review the latest revision before saving.')
    return item


def event(workspace, item, action, fields=()):
    if len(item['events']) >= MAX_EVENTS:
        raise ImportProblem('Investigation history limit reached; start a linked next question.')
    at = now()
    item['revision'] += 1
    item['updated_at'] = at
    # Field names and dispositions trace mutation without duplicating excerpts or
    # auth metadata in a hidden historical copy.
    item['events'].append({'at': at, 'revision': item['revision'], 'action': action,
                           'changed_fields': sorted(fields), 'status': item['status'],
                           'decision': item['decision'], 'actor': 'local operator'})
    workspace['history'].append({'at': at, 'action': 'investigation ' + action,
                                 'detail': 'Investigation revision ' + str(item['revision']),
                                 'investigation_id': item['id'], 'revision': item['revision']})


def values(workspace, data, previous=None):
    result = {k: '' for k in TEXT_LIMITS}
    result.update(subject=None, status='open', decision='undecided', access_mode='anonymous', evidence_refs=[], execution_context=None)
    if previous:
        result.update({k: copy.deepcopy(previous.get(k, result.get(k))) for k in EDITABLE})
    if 'execution_context' in data:
        result['execution_context'] = execution_expectation(data['execution_context'])
    for field in TEXT_LIMITS:
        if field in data:
            result[field] = text(data[field], field, required=field == 'question')
    if not result['question']:
        raise ImportProblem('Question is required.')
    if 'subject' in data:
        result['subject'] = subject(workspace, data['subject'])
    if 'evidence_refs' in data:
        result['evidence_refs'] = evidence(workspace, data['evidence_refs'])
    for field, allowed in (('status', STATUSES), ('decision', DECISIONS), ('access_mode', ('anonymous', 'authenticated'))):
        if field in data:
            if data[field] not in allowed:
                raise ImportProblem('Unsupported investigation ' + field.replace('_', ' ') + '.')
            result[field] = data[field]
    reference = result['access_reference']
    if reference and not re.fullmatch(r'ref:[A-Za-z0-9][A-Za-z0-9._-]{0,95}', reference):
        raise ImportProblem('Use an opaque identity label such as ref:test-account-a; never a password, token or live session ID.')
    if result['access_mode'] == 'anonymous':
        result['access_role'] = result['access_reference'] = ''
    return result


def save(workspace, data):
    request(data, EDITABLE | {'id', 'revision'})
    ensure(workspace)
    if data.get('id'):
        item = get(workspace, data)
        updates = values(workspace, data, item)
        changed = [key for key, value in updates.items() if item.get(key) != value]
        if changed:
            item.update(updates)
            event(workspace, item, 'updated', changed)
        return item
    if len(workspace['investigations']) >= MAX_INVESTIGATIONS:
        raise ImportProblem(f'Use at most {MAX_INVESTIGATIONS} investigations per workspace.')
    if data.get('revision') not in (None, 0):
        raise ImportProblem('A new investigation has no prior revision.')
    at = now()
    item = {'id': uuid.uuid4().hex, 'schema': 'atlas-investigation/1', 'revision': 0,
            'created_at': at, 'updated_at': at, **values(workspace, data), 'tests': [],
            'finding_record_id': None, 'next_investigation_ids': [], 'events': []}
    workspace['investigations'].append(item)
    event(workspace, item, 'created', EDITABLE)
    return item


def safe_url(value):
    """Snapshot public URL structure only, with userinfo/query/fragment removed."""
    if not isinstance(value, str) or len(value) > 2000:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            return None
        hostname = parsed.hostname
        if ':' in hostname:
            hostname = '[' + hostname + ']'
        authority = hostname + (':' + str(parsed.port) if parsed.port else '')
        return clean(urlunsplit((parsed.scheme, authority, parsed.path, '', '')))
    except ValueError:
        return None


def execution_expectation(value):
    """An operator expectation, never a caller assertion of measured routes."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'host_id', 'interface'}:
        raise ImportProblem('Execution context requires only a host ID and expected interface.')
    if not isinstance(value['host_id'], str) or not re.fullmatch(r'[0-9a-f]{32}', value['host_id']):
        raise ImportProblem('Select the execution host reported by this Atlas server.')
    if not isinstance(value['interface'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value['interface']):
        raise ImportProblem('Choose an expected interface or the explicit system route policy.')
    return copy.deepcopy(value)


def execution_snapshot(value):
    """Allowlisted historical measurements; no preview/session capability survives."""
    if not isinstance(value, dict):
        return None
    result = {}
    for key in ('host_id', 'host_name', 'platform', 'interface', 'checked_at', 'route_policy', 'policy'):
        if isinstance(value.get(key), str):
            result[key] = clean(value[key])[:200]
    host = value.get('host')
    if isinstance(host, dict):
        result['host'] = {key: clean(host[key])[:200] for key in ('id', 'name', 'platform') if isinstance(host.get(key), str)}
    result['routes'] = []
    for route in value.get('routes', [])[:80] if isinstance(value.get('routes'), list) else []:
        if isinstance(route, dict):
            retained = {key: clean(route[key])[:200] for key in ('target', 'interface', 'source', 'gateway', 'table') if isinstance(route.get(key), str)}
            for key in ('ifindex', 'table'):
                if isinstance(route.get(key), int) and not isinstance(route[key], bool) and 0 <= route[key] <= 4294967295:
                    retained[key] = route[key]
            result['routes'].append(retained)
    return result


def run_snapshot(run):
    """Strictly derive a snapshot from retained server metadata, not client config."""
    snapshot = {key: run.get(key) for key in ('kind', 'state', 'started_at', 'ended_at')}
    for key in ('requests', 'skipped', 'findings'):
        value = run.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10000000:
            snapshot[key] = value
    state = run.get('state')
    snapshot['completeness'] = ('in progress' if state in ('queued', 'running') else
                                'incomplete' if state in ('partial', 'failed', 'interrupted', 'cancelled', 'stopped', 'blocked', 'timeout') else
                                'completed run; interpretation required' if state == 'completed' else 'unknown')
    snapshot['proof_limits'] = 'Run state is execution metadata, not a negative test or validated impact. Authentication must be re-established before another run.'
    plan = run.get('plan') if isinstance(run.get('plan'), dict) else {}
    execution = execution_snapshot(plan.get('execution_context'))
    if execution:
        snapshot['execution_context'] = execution
    if isinstance(plan.get('resumes_run_id'), str) and re.fullmatch(r'[0-9a-f]{32}', plan['resumes_run_id']):
        snapshot['resumes_run_id'] = plan['resumes_run_id']
    if state not in ('queued', 'running', 'completed'):
        snapshot['reason'] = clean(str(run.get('reason', '')))[:1000]
    configured_auth = plan.get('authentication') if isinstance(plan.get('authentication'), dict) else {}
    observed_auth = run.get('authentication') if isinstance(run.get('authentication'), dict) else {}
    mode = observed_auth.get('mode', configured_auth.get('mode', 'unknown'))
    if mode not in ('unknown', 'unauthenticated', 'unverified request', 'transient origin-bound session', 'session credentials', 'anonymous control'):
        mode = 'unknown'
    auth = {'mode': mode, 'session_verified': observed_auth.get('session_verified') is True}
    generation = observed_auth.get('generation')
    if isinstance(generation, int) and not isinstance(generation, bool) and 0 <= generation <= 1000000:
        auth['generation'] = generation
    snapshot['authentication'] = auth
    context = {}
    for key in ('max_requests', 'max_seconds', 'delay_ms', 'max_depth', 'path_count', 'payload_count'):
        value = plan.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100000:
            context[key] = value
    for key in ('vantage', 'namespace'):
        if isinstance(plan.get(key), str):
            context[key] = clean(plan[key])[:500]
    url = safe_url(plan.get('url'))
    if url:
        context['url'] = url
    origins = plan.get('origins')
    if isinstance(origins, list):
        context['origins'] = [url for value in origins[:16] if (url := safe_url(value))]
    elif isinstance(origins, dict):
        context['origins'] = [url for origin, prefix in list(origins.items())[:16]
                              if isinstance(origin, str) and isinstance(prefix, str) and (url := safe_url(origin + prefix))]
    # A typed terminal operation is retained as a small semantic plan, never argv,
    # environment, shell input, arbitrary headers or response content.
    operation = plan.get('operation')
    if isinstance(operation, dict):
        from .host_operations import PROFILES, target_ip, ports
        try:
            if isinstance(operation.get('profile'), str) and operation['profile'] in PROFILES:
                safe_operation = {'profile': operation['profile'], 'target': target_ip(operation.get('target'))}
                if isinstance(operation.get('interface'), str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', operation['interface']):
                    safe_operation['interface'] = operation['interface']
                timeout = operation.get('timeout')
                if isinstance(timeout, int) and not isinstance(timeout, bool) and 15 <= timeout <= 600:
                    safe_operation['timeout'] = timeout
                if operation.get('profile') == 'service-enumeration':
                    safe_operation['ports'] = ports(operation.get('ports'))
                if operation.get('profile') == 'http-headers' and (url := safe_url(operation.get('url'))):
                    safe_operation['url'] = url
                context['operation'] = safe_operation
        except ImportProblem:
            pass
    snapshot['context'] = context
    return snapshot


def link_run(workspace, data):
    request(data, {'id', 'revision', 'run_id'})
    item = get(workspace, data)
    run = next((r for r in workspace.get('web_runs', []) if r['id'] == data.get('run_id')), None)
    if not run:
        raise ImportProblem('Run is outside this workspace.')
    existing = next((t for t in item['tests'] if t['run_id'] == run['id']), None)
    snapshot = run_snapshot(run)
    if existing:
        if existing['snapshot'] != snapshot:
            existing['snapshot'] = snapshot
            event(workspace, item, 'test refreshed', ['tests'])
    else:
        if len(item['tests']) >= MAX_TESTS:
            raise ImportProblem(f'Use at most {MAX_TESTS} runs per investigation.')
        item['tests'].append({'run_id': run['id'], 'linked_at': now(), 'snapshot': snapshot})
        event(workspace, item, 'test linked', ['tests'])
    return item


def resume_source(workspace, item, run_id):
    if not isinstance(run_id, str) or run_id not in {test['run_id'] for test in item['tests']}:
        raise ImportProblem('Choose an incomplete run linked to this investigation.')
    run = next((row for row in workspace.get('web_runs', []) if row['id'] == run_id), None)
    if not run or run.get('state') not in ('partial', 'failed', 'interrupted', 'cancelled', 'stopped', 'blocked', 'timeout'):
        raise ImportProblem('Only an incomplete, stopped run can be prepared again. Stop active tests first.')
    if run.get('kind') not in ('request', 'crawl', 'payload', 'scanner', 'matrix'):
        raise ImportProblem('Prepare this tool manually from its retained evidence. Automatic shell, proxy and socket replay is unavailable.')
    return run


def resume_preparation(workspace, data):
    """A nonmutating preparation, with no executable request or restored authority."""
    request(data, {'id', 'revision', 'run_id'})
    item = get(workspace, data)
    if item['status'] == 'closed':
        raise ImportProblem('Reopen this investigation before preparing another test.')
    run = resume_source(workspace, item, data.get('run_id'))
    snapshot = run_snapshot(run)
    context = snapshot['context']
    config = {key: context[key] for key in ('url', 'max_requests', 'max_seconds', 'delay_ms', 'max_depth') if key in context}
    if not config.get('url'):
        raise ImportProblem('The original run has no reviewed URL. Prepare a fresh scoped test manually from its evidence.')
    from .web_transport import Scope, path_key
    from .web_evidence import web_url
    origin, path, *_ = web_url(config['url'])
    plan = run.get('plan') if isinstance(run.get('plan'), dict) else {}
    origins = plan.get('origins', {})
    prefix = origins.get(origin) if isinstance(origins, dict) else None
    config['path_prefix'] = path_key(prefix if isinstance(prefix, str) else path)
    config['exclude_paths'] = copy.deepcopy(plan.get('excluded_paths', []))
    config['extra_origins'] = []
    # Validate the retained subset without resolving names or opening sockets.
    reviewed = Scope({**config, 'authorized': True}, resolve=False)
    reviewed.check(config['url'])
    return {'resume_preparation': {'kind': run['kind'], 'config': config,
            'resumes_run_id': run['id'], 'limitations': [
                'A new bounded run will be linked to the original; completed requests are not replayed automatically.',
                'Review the exact URL, scope and test settings. Query strings, bodies, headers and payloads were not restored.',
                'Check the current execution host and route, then establish authentication and confirm authority again.',
                'The original incomplete run and its evidence remain unchanged.']}}


def link_evidence(workspace, data):
    request(data, {'id', 'revision', 'observation_id', 'relation'})
    item = get(workspace, data)
    ref = evidence(workspace, [{'observation_id': data.get('observation_id'), 'relation': data.get('relation')}])[0]
    refs = [r for r in item['evidence_refs'] if r['observation_id'] != ref['observation_id']] + [ref]
    refs = evidence(workspace, refs)
    if refs != item['evidence_refs']:
        item['evidence_refs'] = refs
        event(workspace, item, 'evidence linked', ['evidence_refs'])
    return item


def finding(workspace, data):
    request(data, {'id', 'revision', 'title', 'details', 'severity', 'evidence_ids'})
    item = get(workspace, data, check_revision=False)
    if item['finding_record_id']:
        # The exact duplicate click is safe even with the now stale revision.
        # It cannot edit the finding or create another one.
        return item
    get(workspace, data)
    refs = copy.deepcopy(item['evidence_refs'])
    if 'evidence_ids' in data:
        selected = data['evidence_ids']
        if not isinstance(selected, list) or len(selected) > MAX_EVIDENCE or any(not isinstance(key, str) for key in selected) or len(set(selected)) != len(selected):
            raise ImportProblem('Choose a bounded list of linked observation IDs.')
        if set(selected) - {ref['observation_id'] for ref in refs}:
            raise ImportProblem('Finding evidence must be linked to this investigation.')
        refs = [ref for ref in refs if ref['observation_id'] in selected]
    if not refs:
        raise ImportProblem('Link evidence before creating a finding. A question alone is not finding evidence.')
    title = text(data.get('title', item['question']), 'question', required=True)
    if len(title) > 240:
        raise ImportProblem('Finding title must contain 1–240 characters.')
    details = text(data.get('details', ''), 'rationale', required=True)
    severity = data.get('severity', 'unrated')
    if severity not in ('unrated', 'info', 'low', 'medium', 'high', 'critical'):
        raise ImportProblem('Choose a supported finding severity.')
    record = {'id': uuid.uuid4().hex, 'kind': 'finding', 'subject': item['subject'],
              'title': title, 'details': details, 'status': 'open', 'at': now(),
              'evidence_refs': ', '.join(r['observation_id'] for r in refs),
              'structured_evidence_refs': refs,
              'investigation_id': item['id'], 'validation': 'operator-authored; not independently validated',
              'severity': severity, 'proof_limits': PROOF_LIMITS, 'actor': 'local operator'}
    workspace['records'].append(record)
    item['finding_record_id'] = record['id']
    event(workspace, item, 'finding drafted', ['finding_record_id'])
    return item


def next_question(workspace, data):
    request(data, {'id', 'revision', 'question', 'objective', 'subject'})
    item = get(workspace, data)
    question = text(data.get('question'), 'question', required=True)
    if len(item['next_investigation_ids']) >= 50:
        raise ImportProblem('Use at most fifty linked next questions.')
    following = save(workspace, {'question': question, 'objective': data.get('objective', item['objective']),
                                  'subject': data.get('subject', item['subject']),
                                  'access_mode': item['access_mode'], 'access_role': item['access_role'],
                                  'access_reference': item['access_reference'],
                                  'execution_context': item.get('execution_context')})
    item['next_investigation_ids'].append(following['id'])
    event(workspace, item, 'next question created', ['next_investigation_ids'])
    return following


def export_filter(workspace, retained_subjects, observation_ids):
    """Keep only references resolvable in this selected export; disclose omissions."""
    rows = [i for i in workspace.get('investigations', []) if not i['subject'] or i['subject'] in retained_subjects]
    workspace['investigations'] = rows
    known = {i['id'] for i in rows}
    records = {r['id'] for r in workspace['records']}
    runs = {r['id'] for r in workspace.get('web_runs', [])}
    for run in workspace.get('web_runs', []):
        plan = run.get('plan')
        if isinstance(plan, dict) and 'investigation_id' in plan and plan['investigation_id'] not in known:
            plan['investigation_id'] = None
            run['export_investigation_omitted'] = True
    for entry in workspace['history']:
        if 'investigation_id' in entry and entry['investigation_id'] not in known:
            entry['investigation_id'] = None
            entry['export_investigation_omitted'] = True
    for item in rows:
        original = len(item['evidence_refs'])
        item['evidence_refs'] = [r for r in item['evidence_refs'] if r['observation_id'] in observation_ids]
        item['export_omitted_evidence_count'] = original - len(item['evidence_refs'])
        item['tests'] = [t for t in item['tests'] if t['run_id'] in runs]
        item['next_investigation_ids'] = [key for key in item['next_investigation_ids'] if key in known]
        if item['finding_record_id'] not in records:
            item['finding_record_id'] = None
    for record in workspace['records']:
        if 'investigation_id' not in record:
            continue
        if record['investigation_id'] not in known:
            record['investigation_id'] = None
        refs = record.get('structured_evidence_refs', [])
        selected = [r for r in refs if r['observation_id'] in observation_ids]
        record['export_omitted_evidence_count'] = len(refs) - len(selected)
        record['structured_evidence_refs'] = selected
        record['evidence_refs'] = ', '.join(r['observation_id'] for r in selected)


def redact(workspace):
    for item in workspace.get('investigations', []):
        for field in TEXT_LIMITS:
            item[field] = '[withheld]'
        item['execution_context'] = '[withheld]'
        for test in item['tests']:
            test['snapshot']['context'] = '[withheld]'
            if 'execution_context' in test['snapshot']:
                test['snapshot']['execution_context'] = '[withheld]'
            if 'reason' in test['snapshot']:
                test['snapshot']['reason'] = '[withheld]'
    for record in workspace['records']:
        if 'structured_evidence_refs' in record:
            # Opaque internal IDs and relationship labels are safe; free text is
            # already withheld by Store.export's ordinary record redaction.
            record['proof_limits'] = PROOF_LIMITS
