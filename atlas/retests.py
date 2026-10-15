"""Durable, non-executing retest records over shared assessment evidence.

A disposition is an operator assessment in the recorded context, never automatic
closure of the original finding or an assertion of independently verified repair.
"""
import copy
import datetime as dt
import hashlib
import json
import re
import uuid

from . import investigations
from .importers import ImportProblem, clean

VERSION = 1
MAX_RETESTS = 200
MAX_EVENTS = 500
STATUSES = ('open', 'in progress', 'complete')
OUTCOMES = ('unknown', 'resolved', 'still present', 'inconclusive')
TEXT_LIMITS = {'question': 1000, 'rationale': 8000, 'next_action': 2000}
EDITABLE = set(TEXT_LIMITS) | {'status', 'outcome', 'evidence_refs'}
CREATE_FIELDS = {'original_collection', 'original_id', 'request_id', 'baseline_evidence_ids'}
PROOF_LIMITS = ('Operator-reported retest assessment; not independently validated. '
                'A reported resolution applies only to the documented tested context. '
                'Missing scanner results, incomplete coverage, failed authentication or '
                'a completed run alone do not establish remediation. Original findings '
                'and evidence remain unchanged.')


def ensure(workspace):
    changed = False
    if 'retests_version' not in workspace:
        workspace['retests_version'] = VERSION
        changed = True
    if type(workspace['retests_version']) is not int or workspace['retests_version'] != VERSION:
        raise ImportProblem('Unsupported retest schema; preserve this workspace and use its compatible application version.')
    if 'retests' not in workspace:
        workspace['retests'] = []
        changed = True
    if not isinstance(workspace['retests'], list):
        raise ImportProblem('Invalid retest collection; preserve this workspace.')
    if any(not isinstance(row, dict) or row.get('schema') != 'atlas-retest/1' for row in workspace['retests']):
        raise ImportProblem('Unsupported retest record schema; preserve this workspace and use its compatible application version.')
    return changed


def request(data, fields):
    if not isinstance(data, dict) or set(data) - (set(fields) | {'workspace'}):
        raise ImportProblem('Unsupported retest fields. Credentials, request configurations and live session state cannot be saved here.')


def get(workspace, data, check_revision=True):
    ensure(workspace)
    item = next((row for row in workspace['retests'] if row['id'] == data.get('id')), None)
    if not item:
        raise ImportProblem('Retest not found in this workspace.')
    if check_revision:
        revision = data.get('revision')
        if isinstance(revision, bool) or not isinstance(revision, int) or revision != item['revision']:
            raise ImportProblem('Retest changed. Refresh and review the latest revision before saving.')
    return item


def original(workspace, collection, key):
    if collection not in ('records', 'findings'):
        raise ImportProblem('Choose a manual finding or scanner assertion from this assessment.')
    row = next((row for row in workspace[collection] if row['id'] == key), None)
    if not row or (collection == 'records' and row.get('kind') != 'finding'):
        raise ImportProblem('Original finding is outside this workspace or is not a finding.')
    return row


def baseline_candidates(workspace, row):
    """Only server-retained original references; never infer validity from absence."""
    observations = {o['id']: o for o in workspace['observations']}
    refs = row.get('structured_evidence_refs', row.get('evidence_refs', []))
    if isinstance(refs, str):
        refs = re.split(r'[\s,]+', refs)
    if not isinstance(refs, list):
        refs = []
    keys = []
    for ref in refs:
        key = ref.get('observation_id') if isinstance(ref, dict) else ref
        if isinstance(key, str) and key in observations and key not in keys:
            keys.append(key)
    # Legacy scanner findings carry a source/subject rather than structured IDs.
    # This is source context, not proof that every source observation supports it.
    if not keys and row.get('import_id'):
        keys = [o['id'] for o in workspace['observations']
                if o.get('import_id') == row['import_id'] and o['subject'] == row.get('subject')]
    return keys[:investigations.MAX_EVIDENCE]


def snapshot(row):
    result = {key: clean(str(row.get(key, '')))[:1000]
              for key in ('title', 'status', 'severity', 'validation', 'origin')}
    result['subject'] = row.get('subject')
    result['proof_limits'] = 'Frozen source summary, not independent verification. Source evidence retains its original claim level.'
    return result


def occurrence_subjects(workspace, item):
    subject = item.get('original_snapshot', {}).get('subject')
    if subject:
        return {subject}
    # Legacy manual findings can have no selected subject while carrying exact
    # structured evidence. Use those explicit baseline subjects, without editing
    # the original or inventing a canonical identity.
    ids = {ref['observation_id'] for ref in item.get('baseline_refs', [])}
    return {o['subject'] for o in workspace['observations'] if o['id'] in ids}


def new_support(workspace, previous, refs):
    """Check provenance/occurrence, without promoting it to validation."""
    baseline = {ref['observation_id'] for ref in previous.get('baseline_refs', [])}
    observations = {o['id']: o for o in workspace['observations']}
    artifacts = {row['id']: row for row in workspace['imports']}
    entities = {row['id']: row for row in workspace['entities']}
    subjects = [entities[key] for key in occurrence_subjects(workspace, previous) if key in entities]
    found = []
    for ref in refs:
        observation = observations[ref['observation_id']]
        artifact = artifacts.get(observation.get('import_id'), {})
        candidate = entities.get(observation['subject'])
        same = candidate and any(candidate['id'] == subject['id'] or
                (candidate.get('key') == subject.get('key') and candidate.get('kind') == subject.get('kind')
                 and candidate.get('namespace') == subject.get('namespace')
                 and candidate.get('label') == subject.get('label')
                 and sorted(candidate.get('addresses', [])) == sorted(subject.get('addresses', []))) for subject in subjects)
        fresh = artifact.get('imported_at', '') >= previous.get('created_at', '9999')
        if observation.get('collected_at'):
            try:
                fresh = fresh and dt.datetime.fromisoformat(observation['collected_at'].replace('Z', '+00:00')) >= dt.datetime.fromisoformat(previous['created_at'])
            except (ValueError, TypeError, KeyError):
                fresh = False
        # Reused identifiers remain separate entities. This equality is an
        # explicit occurrence-context gate, never an identity reconciliation.
        if (ref['relation'] == 'supporting' and observation['id'] not in baseline
                and observation['status'] == 'observed' and same
                and fresh):
            found.append(observation)
    return found


def values(workspace, data, previous=None):
    result = {'question': '', 'rationale': '', 'next_action': '',
              'status': 'open', 'outcome': 'unknown', 'evidence_refs': []}
    if previous:
        result.update({key: copy.deepcopy(previous[key]) for key in EDITABLE})
    for field, limit in TEXT_LIMITS.items():
        if field in data:
            value = data[field]
            if not isinstance(value, str) or len(value) > limit:
                raise ImportProblem(f'{field.replace("_", " ").capitalize()} must contain at most {limit} characters.')
            result[field] = clean(value.strip())
    if not result['question']:
        raise ImportProblem('Retest question is required.')
    for field, allowed in (('status', STATUSES), ('outcome', OUTCOMES)):
        if field in data:
            if data[field] not in allowed:
                raise ImportProblem('Unsupported retest ' + field + '.')
            result[field] = data[field]
    if 'evidence_refs' in data:
        result['evidence_refs'] = investigations.evidence(workspace, data['evidence_refs'])
    if result['outcome'] != 'unknown' and not result['rationale']:
        raise ImportProblem('Explain the tested context, interpretation and coverage limits before reporting a retest outcome.')
    if result['outcome'] in ('resolved', 'still present'):
        supporting = new_support(workspace, previous or {}, result['evidence_refs'])
        if not supporting:
            raise ImportProblem('A reported resolution or still-present outcome requires new supporting observed evidence for the original occurrence, collected after this retest was created. Original, unrelated or inferred advisory evidence alone is insufficient.')
        linked = next((row for row in workspace.get('investigations', [])
                       if row['id'] == (previous or {}).get('investigation_id')), None)
        run_ids = {test['run_id'] for test in linked['tests']} if linked else set()
        runs = [run for run in workspace.get('web_runs', []) if run['id'] in run_ids]
        if result['outcome'] == 'resolved' and runs:
            latest = max(runs, key=lambda run: run.get('started_at', ''))
            if latest['state'] != 'completed':
                raise ImportProblem('The latest linked retest run is incomplete or active. Record inconclusive, or review a fresh completed test before reporting resolution.')
            if not any(o.get('import_id') in latest.get('import_ids', []) for o in supporting):
                raise ImportProblem('A reported resolution must include supporting observed evidence from the latest completed linked retest run.')
    if result['status'] == 'complete' and result['outcome'] == 'unknown':
        raise ImportProblem('Choose an explicit retest outcome before marking this retest complete.')
    return result


def event(workspace, item, action, fields):
    if len(item['events']) >= MAX_EVENTS:
        raise ImportProblem('Retest history limit reached; start a separately linked retest.')
    at = investigations.now()
    item['revision'] += 1
    item['updated_at'] = at
    item['events'].append({'at': at, 'revision': item['revision'], 'action': action,
                           'changed_fields': sorted(fields), 'status': item['status'],
                           'outcome': item['outcome'], 'actor': 'local operator'})
    workspace['history'].append({'at': at, 'action': 'retest ' + action,
                                 'detail': 'Retest revision ' + str(item['revision']),
                                 'retest_id': item['id'], 'revision': item['revision']})


def save(workspace, data):
    request(data, EDITABLE | CREATE_FIELDS | {'id', 'revision'})
    ensure(workspace)
    if data.get('id'):
        if set(data) & CREATE_FIELDS:
            raise ImportProblem('The original finding and baseline are immutable; create another retest for a new baseline.')
        item = get(workspace, data)
        updates = values(workspace, data, item)
        changed = [key for key, value in updates.items() if item[key] != value]
        if changed:
            item.update(updates)
            event(workspace, item, 'updated', changed)
        return item
    if data.get('revision') not in (None, 0) or isinstance(data.get('revision'), bool):
        raise ImportProblem('A new retest has no prior revision.')
    request_id = data.get('request_id')
    if not isinstance(request_id, str) or not re.fullmatch(r'[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', request_id):
        raise ImportProblem('Create a fresh opaque request ID for this retest.')
    fingerprint = hashlib.sha256(json.dumps({k: v for k, v in data.items() if k != 'workspace'}, sort_keys=True).encode()).hexdigest()
    existing = next((row for row in workspace['retests'] if row['request_id'] == request_id), None)
    if existing:
        if existing['create_fingerprint'] != fingerprint:
            raise ImportProblem('This retest request ID was already used for different content. Refresh the existing retest.')
        return existing
    if len(workspace['retests']) >= MAX_RETESTS:
        raise ImportProblem(f'Use at most {MAX_RETESTS} retests per assessment.')
    row = original(workspace, data.get('original_collection'), data.get('original_id'))
    candidates = baseline_candidates(workspace, row)
    selected = data.get('baseline_evidence_ids', candidates)
    if (not isinstance(selected, list) or len(selected) > investigations.MAX_EVIDENCE
            or any(not isinstance(key, str) for key in selected) or len(set(selected)) != len(selected)
            or set(selected) - set(candidates)):
        raise ImportProblem('Baseline evidence must reference this finding\'s retained original observations.')
    baseline_refs = [{'observation_id': key, 'relation': 'context'} for key in selected]
    at = investigations.now()
    initial = {'question': '', 'rationale': '', 'next_action': '', 'status': 'open',
               'outcome': 'unknown', 'evidence_refs': [], 'baseline_refs': baseline_refs,
               'original_snapshot': snapshot(row), 'created_at': at}
    item = {'id': uuid.uuid4().hex, 'schema': 'atlas-retest/1', 'revision': 0,
            'created_at': at, 'updated_at': at, 'request_id': request_id,
            'create_fingerprint': fingerprint, 'original_collection': data['original_collection'],
            'original_id': row['id'], 'original_snapshot': snapshot(row),
            'baseline_refs': baseline_refs, 'investigation_id': None, 'events': [],
            'proof_limits': PROOF_LIMITS,
            **values(workspace, data, initial)}
    workspace['retests'].append(item)
    event(workspace, item, 'created', EDITABLE | {'original_id', 'baseline_refs'})
    return item


def link_evidence(workspace, data):
    request(data, {'id', 'revision', 'observation_id', 'relation'})
    item = get(workspace, data)
    ref = investigations.evidence(workspace, [{'observation_id': data.get('observation_id'), 'relation': data.get('relation')}])[0]
    refs = [row for row in item['evidence_refs'] if row['observation_id'] != ref['observation_id']] + [ref]
    return save(workspace, {'id': item['id'], 'revision': item['revision'], 'evidence_refs': refs})


def prepare(workspace, data):
    """Create/reuse a question only; never restore execution or authentication."""
    request(data, {'id', 'revision'})
    item = get(workspace, data)
    if item['investigation_id']:
        investigation = investigations.get(workspace, {'id': item['investigation_id']}, check_revision=False)
    else:
        subjects = occurrence_subjects(workspace, item)
        subject = next(iter(subjects)) if len(subjects) == 1 else item['original_snapshot']['subject']
        investigation = investigations.save(workspace, {
            'question': item['question'], 'subject': subject,
            'objective': 'Retest the retained original finding in an explicitly reviewed context. ' + PROOF_LIMITS,
            'next_action': item['next_action'], 'evidence_refs': copy.deepcopy(item['baseline_refs']),
            'access_mode': 'anonymous', 'execution_context': None})
        item['investigation_id'] = investigation['id']
        event(workspace, item, 'investigation prepared', ['investigation_id'])
    # No caller-supplied URL, headers, command, access labels or session is saved.
    # Existing investigation preparation owns target and route/session review.
    return item


def preparation(workspace, item):
    investigation = investigations.get(workspace, {'id': item['investigation_id']}, check_revision=False)
    result = {'investigation_id': investigation['id'], 'investigation_revision': investigation['revision'],
              'limitations': ['Preparation creates no target requests and restores no credentials or execution authority.',
                              'Review the exact target, scope, host and route; re-enter and verify authentication for this retest.',
                              'The original finding and evidence remain unchanged; retest outcomes are operator assessments.']}
    subjects = occurrence_subjects(workspace, item)
    entity = next((e for e in workspace['entities'] if len(subjects) == 1 and e['id'] in subjects), None)
    if entity:
        url = investigations.safe_url(entity.get('label'))
        if url:
            result['config'] = {'url': url}
    return result


def project(workspace):
    """Response-derived linked execution state, never a parallel authoritative copy."""
    ensure(workspace)
    questions = {row['id']: row for row in workspace.get('investigations', [])}
    for item in workspace['retests']:
        linked = questions.get(item.get('investigation_id'))
        item['tests'] = copy.deepcopy(linked['tests']) if linked else []
        item['outcome_label'] = {'resolved': 'reported resolved', 'still present': 'reported still present',
                                 'unknown': 'not assessed', 'inconclusive': 'inconclusive'}[item['outcome']]


def export_filter(workspace, observation_ids):
    originals = {'records': {r['id'] for r in workspace['records'] if r.get('kind') == 'finding'},
                 'findings': {r['id'] for r in workspace['findings']}}
    questions = {row['id'] for row in workspace.get('investigations', [])}
    workspace['retests'] = [row for row in workspace.get('retests', [])
                            if row['original_id'] in originals[row['original_collection']]]
    known = {row['id'] for row in workspace['retests']}
    for item in workspace['retests']:
        for field in ('baseline_refs', 'evidence_refs'):
            refs = item[field]
            item[field] = [ref for ref in refs if ref['observation_id'] in observation_ids]
            item['export_omitted_' + field + '_count'] = len(refs) - len(item[field])
        if item['investigation_id'] not in questions:
            item['investigation_id'] = None
            item['tests'] = []
        # Opaque duplicate-request plumbing is useful locally, not in reports.
        item.pop('request_id', None)
        item.pop('create_fingerprint', None)
    for entry in workspace['history']:
        if 'retest_id' in entry and entry['retest_id'] not in known:
            entry['retest_id'] = None
            entry['export_retest_omitted'] = True


def redact(workspace):
    for item in workspace.get('retests', []):
        for field in TEXT_LIMITS:
            item[field] = '[withheld]'
        for field in ('title', 'origin'):
            item['original_snapshot'][field] = '[withheld]'
        for test in item.get('tests', []):
            test['snapshot']['context'] = '[withheld]'
            for field in ('execution_context', 'reason'):
                if field in test['snapshot']:
                    test['snapshot'][field] = '[withheld]'
