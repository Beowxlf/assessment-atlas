"""Independent execution-review API checks against an actual hosted subprocess.

Targets, accounts and databases are disposable synthetic fixtures. Preview must
perform no target TCP connection; process restart intentionally loses authority.
"""
import copy
import json
import unittest

import test_investigations_api as investigation_fixture


class ExecutionAPITests(unittest.TestCase):
    def setUp(self):
        self.client = investigation_fixture.InvestigationAPITests(methodName='runTest')
        self.client.setUp()
        self.addCleanup(self.client.tearDown)
        self.connections = []
        original = self.client.target.get_request

        def accepted():
            connection = original()
            self.connections.append(connection[1])
            return connection

        self.client.target.get_request = accepted
        self.key = self.client.create()
        self.context = self.client.execution(self.key)

    def config(self, inv, **changes):
        return self.client.config(**{'url': self.client.url + '/public', 'investigation_id': inv['id'],
                                     'investigation_revision': inv['revision'], 'execution_context': self.context, 'execution_kind': 'scanner',
                                     'access_role': inv['access_role'], 'access_reference': inv['access_reference'], **changes})

    def review(self, config, workspace=None):
        result = self.client.post('execution/preview', {'workspace': workspace or self.key, **config})
        return {**config, 'context_token': result['token']}, result

    def rejected(self, config, workspace=None, kind='scanner', **headers):
        before = self.client.workspace(workspace or self.key)
        calls, connections = len(self.client.target.seen), len(self.connections)
        code, _, error = self.client.request('/api/web/start', {'workspace': workspace or self.key, 'kind': kind, 'config': config}, **headers)
        self.assertEqual(code, 400, error)
        self.assertEqual(self.client.workspace(workspace or self.key).get('web_runs', []), before.get('web_runs', []))
        self.assertEqual(len(self.client.target.seen), calls)
        self.assertEqual(len(self.connections), connections)

    def test_status_is_authenticated_and_preview_is_scoped_dns_without_target_connection(self):
        client = self.client
        self.assertEqual(client.request('/api/execution/status?workspace=' + self.key, Cookie='')[0], 401)
        status = client.get('/api/execution/status?workspace=' + self.key)
        self.assertTrue(status['host']['id'])
        self.assertTrue(status['host']['platform'])
        self.assertTrue(any(row['name'] == self.context['interface'] for row in status['interfaces']))
        inv = client.investigation(self.key)
        config = self.config(inv)
        for headers in ({'Cookie': ''}, {'X-Atlas-Nonce': 'synthetic-wrong-nonce'}, {'Origin': 'https://outside.invalid'}):
            self.assertEqual(client.request('/api/execution/preview', {'workspace': self.key, **config}, **headers)[0], 403)
        for changed in ({'authorized': False}, {'execution_context': {'host_id': 'operator-browser', 'interface': self.context['interface']}},
                        {'execution_context': {**self.context, 'interface': 'nonexistent-fixture-interface'}}):
            code, _, error = client.request('/api/execution/preview', {'workspace': self.key, **config, **changed})
            self.assertEqual(code, 400, error)
        _, preview = self.review(config)
        self.assertEqual(preview['host']['id'], self.context['host_id'])
        self.assertEqual(preview['interface'], self.context['interface'])
        self.assertTrue(preview['routes'])
        self.assertGreater(preview['expires_in'], 0)
        self.assertTrue(preview['scope_digest'])
        self.assertEqual(self.connections, [], 'Preview must not even open a target TCP connection')
        self.assertEqual(client.target.seen, [])

    def test_current_review_binds_scope_interface_owner_workspace_and_is_not_stored(self):
        client = self.client
        inv = client.investigation(self.key)
        config = self.config(inv)
        self.rejected(config)
        for changed in ({'url': client.url + '/changed'}, {'path_prefix': '/public'}, {'exclude_paths': ['/excluded']},
                        {'max_requests': 19}, {'method': 'POST'}, {'body': 'synthetic changed request body'},
                        {'http_version': 'http2'}, {'investigation_revision': inv['revision'] + 1},
                        {'resumes_run_id': 'a' * 32},
                        {'execution_context': {**self.context, 'interface': 'other-fixture-interface'}}):
            prepared, _ = self.review(config)
            self.rejected({**prepared, **changed})
        prepared, _ = self.review(config)
        self.rejected(prepared, kind='crawl')
        prepared, _ = self.review(config)
        self.rejected({**prepared, 'execution_kind': 'crawl'}, kind='crawl')
        code, headers, _ = client.request('/api/login', {'password': client.password})
        self.assertEqual(code, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        other_nonce = client.request('/api/session', Cookie=cookie)[2]['nonce']
        prepared, _ = self.review(config)
        self.rejected(prepared, Cookie=cookie, **{'X-Atlas-Nonce': other_nonce})
        other = client.create()
        other_inv = client.investigation(other)
        prepared, _ = self.review(config)
        self.rejected({**prepared, 'investigation_id': other_inv['id'], 'investigation_revision': other_inv['revision']}, workspace=other)
        prepared, preview = self.review(self.config(inv))
        result = client.post('web/start', {'workspace': self.key, 'kind': 'scanner', 'config': prepared})
        self.assertEqual(client.finished(self.key, result['id'])['state'], 'completed')
        view = client.workspace(self.key)
        self.assertTrue(view['web_runs'][0]['plan']['execution_context'])
        # A token is one execution review, not reusable stored authority.
        prepared['investigation_revision'] = view['investigations'][0]['revision']
        self.rejected(prepared)
        for value in (view, client.post('export', {'workspace': self.key, 'identifiers': True})):
            self.assertNotIn(preview['token'], json.dumps(value))
        self.assertNotIn(preview['token'].encode(), (client.data / 'atlas.sqlite3').read_bytes())
        redacted = client.post('export', {'workspace': self.key})
        self.assertNotIn(client.url, json.dumps(redacted))
        self.assertEqual(redacted['investigations'][0]['execution_context'], '[withheld]')

    def test_authentication_session_change_or_discard_requires_a_new_review_without_anonymous_fallback(self):
        client = self.client
        inv = client.investigation(self.key, access_mode='authenticated', access_role='Synthetic auditor', access_reference='ref:auditor')
        config = self.config(inv, url=client.url + '/private/record')
        session_a, session_b = client.session(self.key, config), client.session(self.key, config)
        config['session_id'] = session_a
        prepared, _ = self.review(config)
        self.rejected({**prepared, 'session_id': session_b})
        prepared, _ = self.review(config)
        client.post('web/session/forget', {'workspace': self.key, 'id': session_a})
        self.rejected(prepared)
        self.assertEqual(client.target.seen, [], 'A stale authenticated session must never fall back to anonymous probes')
        fresh = client.session(self.key, config)
        prepared, _ = self.review({**config, 'session_id': fresh})
        run = client.post('web/start', {'workspace': self.key, 'kind': 'scanner', 'config': prepared})
        self.assertEqual(client.finished(self.key, run['id'])['state'], 'completed')
        stored = json.dumps(client.workspace(self.key))
        self.assertNotIn(investigation_fixture.COOKIE, stored)

    def test_restart_keeps_expectation_and_evidence_but_resume_requires_new_authority_and_run(self):
        client = self.client
        inv = client.investigation(self.key)
        config = self.config(inv, url=client.url + '/public?synthetic-query=PRIVATE_QUERY_VALUE', paths=['/slow'], execution_kind='crawl')
        prepared, preview = self.review(config)
        run = client.post('web/start', {'workspace': self.key, 'kind': 'crawl', 'config': prepared})
        self.assertTrue(client.target.entered.wait(8))
        before = client.workspace(self.key)
        self.assertTrue(before['observations'])
        original_observations = copy.deepcopy(before['observations'])
        client.stop_server()
        client.target.release.set()
        client.start_server()
        restored = client.workspace(self.key)
        inv = restored['investigations'][0]
        self.assertEqual(inv['execution_context'], self.context)
        self.assertEqual(restored['observations'], original_observations)
        self.assertEqual(restored['web_runs'][0]['state'], 'interrupted')
        prepared['investigation_revision'] = inv['revision']
        self.rejected(prepared)
        unchanged = client.workspace(self.key)
        target_calls = list(client.target.seen)
        response = client.post('investigation/resume', {'workspace': self.key, 'id': inv['id'], 'revision': inv['revision'], 'run_id': run['id']})
        resume = response['resume_preparation']
        self.assertEqual(resume['resumes_run_id'], run['id'])
        self.assertEqual(resume['kind'], 'crawl')
        self.assertTrue(resume['limitations'])
        for secret in ('PRIVATE_QUERY_VALUE', 'context_token', 'session_id', 'Authorization', 'Cookie'):
            self.assertNotIn(secret, json.dumps(resume))
        for authority in ('authorized', 'auth', 'headers', 'body'):
            self.assertNotIn(authority, resume['config'])
        self.assertEqual(client.workspace(self.key), unchanged, 'Preparing a resume must not mutate or replace its original run')
        self.assertEqual(client.target.seen, target_calls)
        next_config = {**resume['config'], 'investigation_id': inv['id'], 'investigation_revision': inv['revision'],
                       'execution_context': self.context, 'resumes_run_id': run['id'], 'authorized': True, 'execution_kind': resume['kind'],
                       'access_role': inv['access_role'], 'access_reference': inv['access_reference']}
        self.rejected(next_config)
        next_config, _ = self.review(next_config)
        result = client.post('web/start', {'workspace': self.key, 'kind': resume['kind'], 'config': next_config})
        self.assertNotEqual(result['id'], run['id'])
        self.assertEqual(client.finished(self.key, result['id'])['state'], 'completed')
        after = client.workspace(self.key)
        source = next(row for row in after['web_runs'] if row['id'] == run['id'])
        self.assertEqual(source, unchanged['web_runs'][0])
        self.assertEqual(next(row for row in after['web_runs'] if row['id'] == result['id'])['plan']['resumes_run_id'], run['id'])
        self.assertTrue({row['id'] for row in original_observations}.issubset({row['id'] for row in after['observations']}))
        self.assertEqual(after['investigations'][0]['decision'], 'undecided')
        self.assertEqual(len(after['investigations'][0]['tests']), 2)
        self.assertNotIn(preview['token'], json.dumps(after))


if __name__ == '__main__':
    unittest.main()
