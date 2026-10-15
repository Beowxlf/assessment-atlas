"""Real authenticated HTTP, process restart and bounded Web/API retest acceptance.

The reused harness owns its loopback target, credentials and temporary database;
no external target or operator data is contacted by these checks.
"""
import json
import unittest
import uuid

import test_investigations_api as fixture


class RetestAPI(unittest.TestCase):
    def setUp(self):
        self.h = fixture.InvestigationAPITests(
            methodName='test_http_session_csrf_stale_revision_and_workspace_reference_boundaries')
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def seed(self, key, value='Synthetic baseline'):
        h = self.h
        bundle = {'format': 'atlas-evidence/1',
                  'entities': [{'key': 'retest-fixture', 'kind': 'application', 'label': h.url + '/public', 'addresses': []}],
                  'observations': [{'subject': 'retest-fixture', 'kind': 'response', 'status': 'observed',
                                    'basis': 'active test', 'value': value}]}
        return h.post('import', {'workspace': key, 'source': 'atlas', 'filename': 'synthetic-retest.json',
                                 'content': json.dumps(bundle), 'context': {'namespace': 'synthetic-retest-api'}})

    def original(self, key):
        h = self.h
        self.seed(key)
        w = h.workspace(key)
        inv = h.investigation(key, subject=w['entities'][0]['id'])
        inv = h.post('investigation/evidence', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'],
                                              'observation_id': w['observations'][0]['id'], 'relation': 'supporting'})['investigations'][0]
        h.post('investigation/finding', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'],
                                        'title': 'Synthetic original finding', 'details': 'Fixture occurrence, not universal proof'})
        return h.workspace(key)['records'][0]

    def create(self, key, row, **changes):
        return self.h.post('retest/save', {'workspace': key, 'original_collection': 'records', 'original_id': row['id'],
                                          'request_id': uuid.uuid4().hex, 'question': 'Does the scoped behavior remain?', **changes})['retests'][-1]

    def test_api_csrf_reference_revision_and_duplicate_preparation_without_execution(self):
        h = self.h
        key, other = h.create(), h.create()
        row = self.original(key)
        request = {'workspace': key, 'original_collection': 'records', 'original_id': row['id'],
                   'request_id': uuid.uuid4().hex, 'question': 'Review the original scoped behavior'}
        first = h.post('retest/save', request)
        second = h.post('retest/save', request)
        self.assertEqual(first['retest_result_id'], second['retest_result_id'])
        item = first['retests'][0]
        calls = list(h.target.seen)
        for action in ('save', 'evidence', 'prepare'):
            data = {'workspace': key, 'id': item['id'], 'revision': item['revision']}
            for headers in ({'Cookie': ''}, {'X-Atlas-Nonce': 'wrong'}, {'Origin': 'https://outside.invalid'}):
                self.assertEqual(h.request('/api/retest/' + action, data, **headers)[0], 403)
            self.assertEqual(h.request('/api/retest/' + action, {**data, 'workspace': other})[0], 400)
        before = h.workspace(key)
        for extra in ({'auth': {'cookies': 'synthetic-secret'}}, {'session_id': 'synthetic-secret'},
                      {'headers': 'synthetic-secret'}, {'baseline_evidence_ids': []}, {'execution_context': {}}):
            code, _, _ = h.request('/api/retest/save', {'workspace': key, 'id': item['id'], 'revision': item['revision'], **extra})
            self.assertEqual(code, 400)
        self.assertEqual(h.workspace(key), before)
        prepared = h.post('retest/prepare', {'workspace': key, 'id': item['id'], 'revision': item['revision']})
        self.assertEqual(h.request('/api/retest/prepare', {'workspace': key, 'id': item['id'], 'revision': item['revision']})[0], 400)
        item = prepared['retests'][0]
        again = h.post('retest/prepare', {'workspace': key, 'id': item['id'], 'revision': item['revision']})
        self.assertEqual(prepared['retest_preparation'], again['retest_preparation'])
        self.assertEqual(len(again['investigations']), 2)
        self.assertEqual(h.target.seen, calls)
        self.assertEqual(again.get('web_runs', []), [])

    def test_restart_preserves_reported_outcome_evidence_originals_and_default_redaction(self):
        h = self.h
        key = h.create()
        row = self.original(key)
        item = self.create(key, row, question='PRIVATE_RETEST_API_QUESTION', next_action='PRIVATE_RETEST_API_NEXT')
        self.seed(key, 'PRIVATE_RETEST_API_NEW_EVIDENCE')
        observation = h.workspace(key)['observations'][-1]
        linked = h.post('retest/evidence', {'workspace': key, 'id': item['id'], 'revision': item['revision'],
                                          'observation_id': observation['id'], 'relation': 'supporting'})
        item = linked['retests'][0]
        complete = h.post('retest/save', {'workspace': key, 'id': item['id'], 'revision': item['revision'],
                                         'outcome': 'still present', 'status': 'complete', 'rationale': 'PRIVATE_RETEST_API_RESULT: bounded contextual interpretation'})
        self.assertEqual(complete['records'][0], row)
        self.assertEqual(complete['retests'][0]['outcome_label'], 'reported still present')
        default = h.post('export', {'workspace': key})
        detailed = h.post('export', {'workspace': key, 'identifiers': True})
        for marker in ('PRIVATE_RETEST_API_QUESTION', 'PRIVATE_RETEST_API_NEXT', 'PRIVATE_RETEST_API_NEW_EVIDENCE', 'PRIVATE_RETEST_API_RESULT'):
            self.assertNotIn(marker, json.dumps(default))
            self.assertIn(marker, json.dumps(detailed))
        cookie = h.cookie
        h.stop_server()
        h.start_server()
        persisted = h.workspace(key)
        self.assertEqual(persisted['retests'], complete['retests'])
        self.assertEqual(persisted['records'], complete['records'])
        self.assertEqual(persisted['observations'], complete['observations'])
        self.assertEqual(h.request('/api/workspaces', Cookie=cookie)[0], 401)

    def test_authenticated_web_test_to_finding_retest_new_run_and_evidence_after_restart(self):
        h = self.h
        key = h.create()
        inv = h.investigation(key, access_mode='authenticated', access_role='Synthetic auditor', access_reference='ref:fixture-auditor')
        config = h.config(namespace='synthetic-retest-api', investigation_id=inv['id'], investigation_revision=inv['revision'], execution_context=h.execution(key))
        config['session_id'] = h.session(key, config)
        config = h.review(key, config)
        baseline = h.post('web/start', {'workspace': key, 'kind': 'scanner', 'config': config})
        self.assertEqual(h.finished(key, baseline['id'])['state'], 'completed')
        workspace = h.workspace(key)
        inv = workspace['investigations'][0]
        resources = {e['id'] for e in workspace['entities'] if e['label'].endswith('/private/record')}
        observation = next(o for o in workspace['observations'] if o['subject'] in resources and o['kind'] == 'HTTP response' and o['value'].get('status') == 200)
        inv = h.post('investigation/evidence', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'],
                                              'observation_id': observation['id'], 'relation': 'supporting'})['investigations'][0]
        h.post('investigation/finding', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'],
                                        'title': 'Synthetic authenticated observation', 'details': 'Bounded original context; no universal access-control conclusion'})
        original = h.workspace(key)['records'][0]
        retest = self.create(key, original)
        prepared = h.post('retest/prepare', {'workspace': key, 'id': retest['id'], 'revision': retest['revision']})
        question = next(row for row in prepared['investigations'] if row['id'] == prepared['retest_preparation']['investigation_id'])
        self.assertEqual(question['access_mode'], 'anonymous')
        self.assertIsNone(question['execution_context'])
        h.stop_server()
        h.start_server()
        self.assertEqual(h.get('/api/web/status?workspace=' + key)['sessions'], [])
        question = h.post('investigation/save', {'workspace': key, 'id': question['id'], 'revision': question['revision'],
                                                'access_mode': 'authenticated', 'access_role': 'Synthetic auditor', 'access_reference': 'ref:fixture-auditor',
                                                'execution_context': h.execution(key)})['investigations'][-1]
        retest_config = h.config(namespace='synthetic-retest-api', investigation_id=question['id'], investigation_revision=question['revision'], execution_context=h.execution(key))
        # The old baseline configuration/session cannot execute after restart.
        seen = list(h.target.seen)
        self.assertEqual(h.request('/api/web/start', {'workspace': key, 'kind': 'scanner', 'config': config})[0], 400)
        self.assertEqual(h.target.seen, seen)
        retest_config['session_id'] = h.session(key, retest_config)
        retest_config = h.review(key, retest_config)
        rerun = h.post('web/start', {'workspace': key, 'kind': 'scanner', 'config': retest_config})
        run = h.finished(key, rerun['id'])
        self.assertEqual(run['state'], 'completed')
        workspace = h.workspace(key)
        retest = workspace['retests'][0]
        new_observation = next(o for o in workspace['observations'] if o['import_id'] in run['import_ids']
                               and o['kind'] == 'HTTP response' and o['value'].get('status') == 200
                               and next(e for e in workspace['entities'] if e['id'] == o['subject'])['label'].endswith('/private/record'))
        linked = h.post('retest/evidence', {'workspace': key, 'id': retest['id'], 'revision': retest['revision'],
                                          'observation_id': new_observation['id'], 'relation': 'supporting'})
        retest = linked['retests'][0]
        result = h.post('retest/save', {'workspace': key, 'id': retest['id'], 'revision': retest['revision'],
                                      'outcome': 'still present', 'status': 'complete',
                                      'rationale': 'The same reviewed synthetic identity still obtains the scoped response. This demonstrates the response, not a security defect by itself.'})
        self.assertEqual(result['retests'][0]['tests'][0]['run_id'], run['id'])
        self.assertEqual(result['records'][0], original)
        self.assertIn('not independently validated', result['retests'][0]['proof_limits'])
        self.assertNotIn(fixture.COOKIE, json.dumps(result))
        self.assertNotIn(fixture.COOKIE.encode(), (h.data / 'atlas.sqlite3').read_bytes())
        h.stop_server()
        h.start_server()
        self.assertEqual(h.workspace(key)['retests'], result['retests'])


if __name__ == '__main__':
    unittest.main()
