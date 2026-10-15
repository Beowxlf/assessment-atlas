"""Independent HTTP/restart acceptance for resumable investigations.

Every database, operator password and target belongs to this synthetic fixture.
The subprocess is deliberately terminated to test actual process-memory loss.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from urllib.parse import urlsplit

from atlas.hosted_auth import save_password
from atlas.store import Store

ROOT = Path(__file__).resolve().parents[1]
TEMP = ROOT / 'work' / 'test-temp'
COOKIE = 'investigation-cookie-SYNTHETIC-ONLY'
MARKER = 'INVESTIGATION_SIGNED_IN_FIXTURE'


class InvestigationTarget(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.seen.append(path)
        signed = COOKIE in self.headers.get('Cookie', '')
        if path == '/slow':
            self.server.entered.set()
            self.server.release.wait(15)
        status, text = 200, 'Synthetic investigation baseline'
        if path == '/guard':
            status, text = (200, MARKER) if signed else (401, 'Sign-in required')
        elif path.startswith('/private'):
            status, text = (200, 'SYNTHETIC_OWNED_RECORD') if signed else (401, 'Sign-in required')
        raw = text.encode()
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            pass  # The interrupted-process case intentionally closes its socket.


class InvestigationAPITests(unittest.TestCase):
    def setUp(self):
        TEMP.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=TEMP)
        self.data = Path(self.temp.name)
        self.password = 'synthetic-investigation-operator-password'
        save_password(self.data / 'operator-auth.json', self.password)
        store = Store(self.data / 'atlas.sqlite3')
        old = store.create('Synthetic legacy assessment', 'No live assessment data')
        # Simulate an actual pre-investigation JSON document, rather than a new
        # document already initialized by the feature under test.
        for field in ('investigations', 'investigations_version'):
            old.pop(field, None)
        with store.connect() as con:
            con.execute('UPDATE workspaces SET body=? WHERE id=?', (json.dumps(old), old['id']))
        self.legacy = old['id']
        self.target = ThreadingHTTPServer(('127.0.0.1', 0), InvestigationTarget)
        self.target.seen = []
        self.target.entered, self.target.release = threading.Event(), threading.Event()
        self.target_thread = threading.Thread(target=self.target.serve_forever, daemon=True)
        self.target_thread.start()
        self.url = 'http://127.0.0.1:' + str(self.target.server_port)
        self.process = None
        self.log = (self.data / 'server.log').open('a', encoding='utf-8')
        self.start_server()

    def tearDown(self):
        self.target.release.set()
        self.stop_server()
        self.target.shutdown()
        self.target.server_close()
        self.target_thread.join(5)
        self.log.close()
        self.temp.cleanup()

    def start_server(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.cookie, self.nonce = '', ''
        environment = {**os.environ, 'PYTHONIOENCODING': 'utf-8'}
        self.process = subprocess.Popen(
            [sys.executable, '-m', 'atlas.server', '--port', str(self.port),
             '--data-dir', str(self.data), '--no-open', '--public-url', 'https://atlas.integration.test'],
            cwd=ROOT, env=environment, stdout=self.log, stderr=self.log,
        )
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail('Fixture Atlas process exited before accepting requests')
            try:
                if self.request('/api/session')[0] == 401:
                    break
            except (OSError, http.client.HTTPException):
                time.sleep(.05)
        else:
            self.fail('Fixture Atlas process did not start')
        code, headers, _ = self.request('/api/login', {'password': self.password})
        self.assertEqual(code, 200)
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.nonce = self.get('/api/session')['nonce']

    def stop_server(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(8)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(5)
            self.process = None

    def request(self, path, data=None, **overrides):
        headers = {'Host': 'atlas.integration.test', 'X-Forwarded-Proto': 'https',
                   'Origin': 'https://atlas.integration.test',
                   'Cookie': self.cookie, 'X-Atlas-Nonce': self.nonce}
        headers.update(overrides)
        if data is not None:
            headers['Content-Type'] = 'application/json'
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        try:
            connection.request('POST' if data is not None else 'GET', path,
                               json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            body = response.read()
            return response.status, dict(response.getheaders()), json.loads(body)
        finally:
            connection.close()

    def get(self, path):
        code, _, result = self.request(path)
        self.assertEqual(code, 200, result)
        return result

    def post(self, path, data):
        code, _, result = self.request('/api/' + path, data)
        self.assertEqual(code, 200, result)
        return result

    def workspace(self, key):
        return self.get('/api/workspace?id=' + key)

    def create(self):
        return self.post('create', {'name': 'Synthetic investigation API acceptance', 'scope': 'Owned loopback fixture only'})['id']

    def investigation(self, key, **changes):
        return self.post('investigation/save', {'workspace': key, 'question': 'Does the controlled record require authentication?', **changes})['investigations'][-1]

    def config(self, **changes):
        return {'url': self.url + '/private/record', 'path_prefix': '/', 'authorized': True,
                'max_requests': 20, 'max_seconds': 30, 'delay_ms': 250, 'max_depth': 0,
                'checks': ['passive'], 'retain_body': True, **changes}

    def session(self, key):
        return self.post('web/session/save', {'workspace': key, 'config': self.config(auth={
            'check_url': self.url + '/guard', 'success_text': MARKER,
            'headers': 'Cookie: session=' + COOKIE,
        })})['id']

    def finished(self, key, run_id):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            row = next(r for r in self.workspace(key)['web_runs'] if r['id'] == run_id)
            if row['state'] not in ('queued', 'running'):
                return row
            time.sleep(.05)
        self.fail('Owned fixture run did not finish')

    def test_http_session_csrf_stale_revision_and_workspace_reference_boundaries(self):
        first, second = self.create(), self.create()
        inv = self.investigation(first)
        for action in ('save', 'run', 'evidence', 'finding', 'next'):
            body = {'workspace': first, 'id': inv['id'], 'revision': inv['revision']}
            for headers in ({'Cookie': ''}, {'X-Atlas-Nonce': 'other-session-nonce'}, {'Origin': 'https://outside.invalid'}):
                self.assertEqual(self.request('/api/investigation/' + action, body, **headers)[0], 403)
        stale = {'workspace': first, 'id': inv['id'], 'revision': inv['revision'], 'question': 'Revised controlled question'}
        self.post('investigation/save', stale)
        self.assertEqual(self.request('/api/investigation/save', stale)[0], 400)
        for action, extra in (('save', {'question': 'Wrong assessment'}), ('run', {'run_id': 'absent'}),
                              ('evidence', {'observation_id': 'absent', 'relation': 'supporting'}),
                              ('finding', {'title': 'Wrong assessment'}), ('next', {'question': 'Wrong assessment'})):
            self.assertEqual(self.request('/api/investigation/' + action,
                                         {'workspace': second, 'id': inv['id'], 'revision': inv['revision'], **extra})[0], 400)
        for extra in ({'access_mode': 'authenticated', 'access_reference': 'Bearer synthetic-secret'},
                      {'headers': {'Authorization': 'Bearer synthetic-secret'}}, {'password': 'synthetic-secret'}):
            self.assertEqual(self.request('/api/investigation/save', {'workspace': first, 'question': 'Reject credential fields', **extra})[0], 400)
        # A valid reference in another assessment must also be rejected.
        other_run = self.post('web/start', {'workspace': second, 'kind': 'crawl', 'config': self.config(url=self.url + '/public')})
        self.finished(second, other_run['id'])
        other_observation = self.workspace(second)['observations'][0]['id']
        inv = self.workspace(first)['investigations'][0]
        for action, extra in (('run', {'run_id': other_run['id']}), ('evidence', {'observation_id': other_observation, 'relation': 'context'})):
            self.assertEqual(self.request('/api/investigation/' + action, {'workspace': first, 'id': inv['id'], 'revision': inv['revision'], **extra})[0], 400)

    def test_authenticated_audit_evidence_finding_and_real_restart_require_fresh_session(self):
        key = self.create()
        inv = self.investigation(key, access_mode='authenticated', access_role='synthetic auditor', access_reference='ref:fixture-auditor',
                                 objective='SYNTHETIC_PRIVATE_OBJECTIVE', rationale='SYNTHETIC_PRIVATE_REASON', next_action='SYNTHETIC_PRIVATE_NEXT')
        session = self.session(key)
        config = self.config(session_id=session, investigation_id=inv['id'], investigation_revision=inv['revision'])
        run = self.post('web/start', {'workspace': key, 'kind': 'scanner', 'config': config})
        self.assertEqual(self.finished(key, run['id'])['state'], 'completed')
        workspace = self.workspace(key)
        inv = workspace['investigations'][0]
        self.assertIn(run['id'], [test['run_id'] for test in inv['tests']])
        record_subjects = {entity['id'] for entity in workspace['entities'] if entity['label'].endswith('/private/record')}
        observation = next(o for o in workspace['observations'] if o['subject'] in record_subjects and o['kind'] == 'HTTP response' and o['value'].get('status') == 200)
        workspace = self.post('investigation/evidence', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'], 'observation_id': observation['id'], 'relation': 'supporting'})
        inv = workspace['investigations'][0]
        body = {'workspace': key, 'id': inv['id'], 'revision': inv['revision'], 'title': 'Synthetic bounded authentication observation', 'details': 'SYNTHETIC_PRIVATE_FINDING: controlled fixture evidence; no universal authorization conclusion.'}
        first = self.post('investigation/finding', body)
        second = self.post('investigation/finding', body)
        self.assertEqual(first['investigations'][0]['finding_record_id'], second['investigations'][0]['finding_record_id'])
        self.assertEqual(len([r for r in second['records'] if r['kind'] == 'finding']), 1)
        inv = second['investigations'][0]
        result = self.post('investigation/next', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'], 'question': 'Compare known object ownership using a separate authorized identity'})
        self.assertEqual(len(result['investigations']), 2)
        default = self.post('export', {'workspace': key})
        detailed = self.post('export', {'workspace': key, 'identifiers': True})
        for private in ('SYNTHETIC_PRIVATE_OBJECTIVE', 'SYNTHETIC_PRIVATE_REASON', 'SYNTHETIC_PRIVATE_NEXT', 'SYNTHETIC_PRIVATE_FINDING', 'ref:fixture-auditor'):
            self.assertNotIn(private, json.dumps(default))
            self.assertIn(private, json.dumps(detailed))
        self.assertNotIn(COOKIE, json.dumps(result))
        self.assertNotIn(COOKIE.encode(), (self.data / 'atlas.sqlite3').read_bytes())
        old_cookie = self.cookie
        self.stop_server()
        self.start_server()
        self.assertEqual(self.request('/api/workspaces', Cookie=old_cookie)[0], 401)
        self.assertEqual(self.get('/api/web/status?workspace=' + key)['sessions'], [])
        persisted = self.workspace(key)
        self.assertEqual(persisted['investigations'], result['investigations'])
        before = list(self.target.seen)
        code, _, failure = self.request('/api/web/start', {'workspace': key, 'kind': 'scanner', 'config': config})
        self.assertEqual(code, 400, failure)
        self.assertEqual(self.target.seen, before, 'An expired session must not fall back to anonymous target probing')
        config['session_id'] = self.session(key)
        config['investigation_revision'] = self.workspace(key)['investigations'][0]['revision']
        rerun = self.post('web/start', {'workspace': key, 'kind': 'scanner', 'config': config})
        self.assertEqual(self.finished(key, rerun['id'])['state'], 'completed')

    def test_process_interruption_preserves_partial_evidence_without_negative_conclusion(self):
        key = self.create()
        inv = self.investigation(key)
        config = self.config(url=self.url + '/public', paths=['/slow'], investigation_id=inv['id'], investigation_revision=inv['revision'])
        run = self.post('web/start', {'workspace': key, 'kind': 'crawl', 'config': config})
        self.assertTrue(self.target.entered.wait(8), 'Owned slow endpoint was not reached')
        before = self.workspace(key)
        self.assertTrue(before['observations'], 'First response must be retained before interrupting the next one')
        self.stop_server()
        self.target.release.set()
        self.start_server()
        after = self.workspace(key)
        interrupted = next(row for row in after['web_runs'] if row['id'] == run['id'])
        self.assertEqual(interrupted['state'], 'interrupted')
        self.assertEqual(after['observations'], before['observations'])
        inv = after['investigations'][0]
        self.assertEqual(inv['decision'], 'undecided')
        self.assertEqual(inv['status'], 'open')
        self.assertEqual(inv['tests'][0]['snapshot']['state'], 'interrupted')
        self.assertIsNone(inv['finding_record_id'])

    def test_preflight_denials_leave_no_orphan_run_and_historical_anonymous_link_stays_anonymous(self):
        key, other = self.create(), self.create()
        authenticated = self.investigation(key, access_mode='authenticated', access_role='Synthetic auditor', access_reference='ref:auditor')
        closed = self.investigation(key, status='closed')
        foreign = self.investigation(other)
        before_calls = list(self.target.seen)
        for inv in (authenticated, closed, foreign):
            config = self.config(url=self.url + '/public', investigation_id=inv['id'], investigation_revision=inv['revision'])
            code, _, error = self.request('/api/web/start', {'workspace': key, 'kind': 'scanner', 'config': config})
            self.assertEqual(code, 400, error)
            self.assertEqual(self.workspace(key).get('web_runs', []), [])
            self.assertEqual(self.target.seen, before_calls)
        # Linking a genuine earlier anonymous run is useful historical context;
        # it must not inherit authenticated status from the current question.
        run = self.post('web/start', {'workspace': key, 'kind': 'scanner', 'config': self.config(url=self.url + '/public')})
        self.finished(key, run['id'])
        result = self.post('investigation/run', {'workspace': key, 'id': authenticated['id'], 'revision': authenticated['revision'], 'run_id': run['id']})
        linked = next(inv for inv in result['investigations'] if inv['id'] == authenticated['id'])
        self.assertEqual(linked['access_mode'], 'authenticated')
        auth = linked['tests'][0]['snapshot']['authentication']
        self.assertEqual(auth['mode'], 'unauthenticated')
        self.assertFalse(auth['session_verified'])
        # Seed a coherent retained-run quota fixture in our stopped, isolated
        # database. No hundred-request target scan is needed to reach the gate.
        quota = self.investigation(other)
        self.stop_server()
        store = Store(self.data / 'atlas.sqlite3')
        fixture = store.get(other)
        item = next(inv for inv in fixture['investigations'] if inv['id'] == quota['id'])
        for _ in range(100):
            retained = {'id': uuid.uuid4().hex, 'kind': 'scanner', 'state': 'completed', 'started_at': '2026-01-01T00:00:00+00:00',
                        'ended_at': '2026-01-01T00:00:01+00:00', 'plan': {'url': self.url + '/public'}, 'requests': 1,
                        'import_ids': [], 'errors': [], 'skipped': 0, 'reason': 'Synthetic quota fixture'}
            fixture.setdefault('web_runs', []).append(retained)
            item['tests'].append({'run_id': retained['id'], 'linked_at': retained['started_at'], 'snapshot': {}})
        with store.connect() as con:
            con.execute('UPDATE workspaces SET body=? WHERE id=?', (json.dumps(fixture), other))
        self.start_server()
        before_calls = list(self.target.seen)
        code, _, error = self.request('/api/web/start', {'workspace': other, 'kind': 'scanner',
                                    'config': self.config(url=self.url + '/public', investigation_id=quota['id'], investigation_revision=quota['revision'])})
        self.assertEqual(code, 400, error)
        self.assertEqual(len(self.workspace(other)['web_runs']), 100)
        self.assertEqual(self.target.seen, before_calls)

    def test_stale_prepared_context_and_invalid_request_method_make_no_requests_or_orphan_run(self):
        key = self.create()
        inv = self.investigation(key)
        prepared = self.config(url=self.url + '/public', investigation_id=inv['id'], investigation_revision=inv['revision'])
        self.post('investigation/save', {'workspace': key, 'id': inv['id'], 'revision': inv['revision'],
                                         'rationale': 'A second synthetic tab revised the test interpretation.'})
        before = list(self.target.seen)
        for endpoint, extra in (('web/start', {'kind': 'scanner'}), ('web/request', {})):
            code, _, error = self.request('/api/' + endpoint, {'workspace': key, 'config': prepared, **extra})
            self.assertEqual(code, 400, error)
            self.assertEqual(self.workspace(key).get('web_runs', []), [])
            self.assertEqual(self.target.seen, before)
        prepared['investigation_revision'] = self.workspace(key)['investigations'][0]['revision']
        marker = 'SYNTHETIC_PRIVATE_INVALID_METHOD'
        code, _, error = self.request('/api/web/request', {'workspace': key, 'config': {**prepared, 'method': marker}})
        self.assertEqual(code, 400, error)
        view = self.workspace(key)
        self.assertEqual(view.get('web_runs', []), [])
        self.assertNotIn(marker, json.dumps(view))
        self.assertEqual(self.target.seen, before)

    def test_legacy_workspace_remains_usable_and_investigation_is_additive(self):
        before = self.workspace(self.legacy)
        self.assertEqual(before['investigations'], [])
        self.assertEqual(before['investigations_version'], 1)
        self.investigation(self.legacy, decision='inconclusive', status='blocked', rationale='Missing permitted test identity', next_action='Obtain an authorized account')
        after = self.workspace(self.legacy)
        for field in ('name', 'scope', 'created_at', 'entities', 'observations', 'records'):
            self.assertEqual(after[field], before[field])
        self.assertEqual(after['investigations'][0]['decision'], 'inconclusive')
        self.assertIsNone(after['investigations'][0]['finding_record_id'])


if __name__ == '__main__':
    unittest.main()
