"""Software-only companion boundaries and a real verified-TLS round trip."""
import datetime as dt
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import ipaddress
import json
import os
from pathlib import Path
import ssl
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from atlas import companion
from atlas.desktop import DesktopRuntime
from atlas.hosted_auth import HostedAuth, save_password
from atlas.importers import ImportProblem
from atlas.server import AtlasServer
from atlas.store import Store
from atlas.vulnerability_data import AdvisoryCache

FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures'
PACKAGE = {'kind': 'package', 'ecosystem': 'npm', 'name': 'atlas-fixture', 'version': '1.2.3'}
CPE = {'kind': 'cpe', 'cpe': 'cpe:2.3:a:atlas_fixture:sample:1.2.3:*:*:*:*:*:*:*'}


class CompanionUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = AdvisoryCache(Path(self.temp.name) / 'cache.sqlite3')

    def test_exact_software_allowlist_excludes_private_asset_fields(self):
        self.assertEqual(companion.software_inventory([PACKAGE, CPE]), [PACKAGE, CPE])
        for rows in ([], [PACKAGE] * 21, ['not an identity'], [{**PACKAGE, 'subject': 'private-asset'}],
                     [{**CPE, 'target': '192.0.2.9'}], [{**PACKAGE, 'evidence_refs': ['private-note']}],
                     [{**PACKAGE, 'password': 'synthetic-private'}], [{'kind': 'package', 'name': 'incomplete'}]):
            with self.subTest(rows=rows), self.assertRaises(ImportProblem):
                companion.software_inventory(rows)

    def test_cache_analysis_is_inert_attributed_and_never_a_clean_verdict(self):
        with patch('socket.create_connection', side_effect=AssertionError('No analysis network')), \
             patch('subprocess.run', side_effect=AssertionError('No analysis execution')):
            for provider in ('nvd', 'osv'):
                self.cache.ingest(provider, (FIXTURES / f'vulnerability-{provider}.json').read_text(encoding='utf-8'))
            result = companion.analyze(self.cache, {'protocol': companion.PROTOCOL, 'inventory': [PACKAGE, CPE]})
            missing = companion.analyze(self.cache, {'protocol': companion.PROTOCOL, 'inventory': [{**PACKAGE, 'version': '9.9.9'}]})
        self.assertEqual(result['inventory_sha256'], companion.inventory_digest([PACKAGE, CPE]))
        self.assertTrue(result['results'][0]['matches'])
        self.assertTrue(result['results'][1]['matches'])
        match = result['results'][0]['matches'][0]
        self.assertEqual(len(match['record_sha256']), 64)
        self.assertEqual(len(match['source_sha256']), 64)
        self.assertFalse(match['publisher_verified'])
        self.assertEqual(missing['results'][0]['matches'], [])
        self.assertIn('not a clean verdict', missing['limit'])
        self.assertNotIn('findings', result)
        for request in ({'protocol': companion.PROTOCOL, 'inventory': [PACKAGE], 'target': '192.0.2.9'},
                        {'protocol': 'unknown', 'inventory': [PACKAGE]}):
            with self.assertRaises(ImportProblem):
                companion.analyze(self.cache, request)

    def test_cache_capacity_and_unknown_applicability_are_explicit(self):
        self.cache.ingest('nvd', (FIXTURES / 'vulnerability-nvd.json').read_text(encoding='utf-8'))
        row = next(row for row in self.cache.records() if companion.match_record(row, CPE)[0] is True)
        with patch.object(self.cache, 'records', return_value=[row] * 5001):
            report = companion.analyze(self.cache, {'protocol': companion.PROTOCOL, 'inventory': [CPE]})
        self.assertTrue(report['cache_truncated'])
        self.assertEqual(report['records_examined'], 5000)
        self.assertEqual(len(report['results'][0]['matches']), 30)
        self.assertEqual(report['results'][0]['matches_omitted'], 4970)
        with patch.object(companion.time, 'monotonic', side_effect=[0, 16]):
            with self.assertRaisesRegex(ImportProblem, 'no clean verdict'):
                companion.analyze(self.cache, {'protocol': companion.PROTOCOL, 'inventory': [CPE]})

    def test_share_review_report_binding_and_expiry_before_evidence_save(self):
        client = companion.Companion()
        client.connections['owner'] = {'origin': 'https://companion.example.test', 'opener': object(), 'nonce': 'synthetic'}
        report = {'protocol': companion.PROTOCOL, 'inventory_sha256': companion.inventory_digest([PACKAGE]), 'results': []}
        with patch.object(companion, 'request_json', return_value=report) as request:
            with self.assertRaisesRegex(ImportProblem, 'allow sharing'):
                client.run('owner', 'workspace', 'asset', {'inventory': [PACKAGE]})
            request.assert_not_called()
            retained = client.run('owner', 'workspace', 'asset', {'inventory': [PACKAGE], 'allow_share': True})
            payload = request.call_args.args[2]
            self.assertEqual(set(payload), {'protocol', 'inventory'})
            self.assertEqual(payload['inventory'], [PACKAGE])
        store = types.SimpleNamespace(capture_selection=lambda *args: self.fail('Rejected report must not save'))
        for owner, workspace in (('other', 'workspace'), ('owner', 'other')):
            with self.assertRaisesRegex(ImportProblem, 'fresh companion report'):
                client.save(owner, workspace, retained['report_id'], store)
        client.reports[retained['report_id']]['at'] = time.monotonic() - 1801
        with self.assertRaisesRegex(ImportProblem, 'fresh companion report'):
            client.save('owner', 'workspace', retained['report_id'], store)
        with patch.object(companion, 'request_json', return_value={**report, 'inventory_sha256': 'wrong'}):
            with self.assertRaisesRegex(ImportProblem, 'does not match'):
                client.run('owner', 'workspace', 'asset', {'inventory': [PACKAGE], 'allow_share': True})
        with patch.object(companion, 'request_json', return_value={}):
            client.disconnect('owner')
        self.assertFalse(client.status('owner')['connected'])
        self.assertEqual(client.reports, {})

    def test_fixed_repository_update_check_only_returns_manual_install_information(self):
        release = {'tag_name': 'v99.0.0', 'html_url': companion.REPOSITORY + '/releases/tag/v99.0.0', 'draft': False, 'prerelease': False,
                   'assets': [{'browser_download_url': 'https://outside.invalid/malicious-code'}]}
        with patch.object(companion, 'secure_opener', return_value='synthetic-opener'), \
             patch.object(companion, 'request_json', return_value=release) as request, \
             patch('subprocess.run', side_effect=AssertionError('Updates cannot execute code')):
            result = companion.check_update()
        request.assert_called_once_with('synthetic-opener', companion.RELEASE_API)
        self.assertTrue(result['newer'])
        self.assertIn('Manual update only', result['policy'])
        self.assertNotIn('assets', result)
        for changes in ({'html_url': 'https://outside.invalid/release'}, {'draft': True}, {'prerelease': True}, {'tag_name': 'shell-code'}):
            with patch.object(companion, 'request_json', return_value={**release, **changes}), self.assertRaises(ImportProblem):
                companion.check_update()

    def test_request_bounds_json_type_tls_context_and_redirect_refusal(self):
        class Response(io.BytesIO):
            headers = types.SimpleNamespace(get_content_type=lambda: 'application/json')
        for body in (b'[]', b'invalid', b'{' + b'x' * companion.MAX_REPLY):
            opener = types.SimpleNamespace(open=lambda *args, **kwargs: Response(body))
            with self.assertRaises(ImportProblem):
                companion.request_json(opener, 'https://service.example.test')
        opener = companion.secure_opener()
        tls = next(h for h in opener.handlers if hasattr(h, '_context'))._context
        self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls.check_hostname)
        with self.assertRaisesRegex(ImportProblem, 'must not redirect'):
            companion.NoRedirect().redirect_request(None, None, 302, None, {}, 'https://outside.invalid')
        for ca in ('-----BEGIN PRIVATE KEY-----', 'not a public certificate', 'x' * 65537):
            with self.assertRaises(ImportProblem):
                companion.secure_opener(ca)


class TLSCompanionTests(unittest.TestCase):
    """Real desktop API and HTTPS transport, with no external network access."""
    def setUp(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest('Optional cryptography package is needed for the verified TLS fixture')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seen = []
        parent = self

        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.forward()
            def do_POST(self):
                self.forward()
            def forward(self):
                content = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                parent.seen.append((self.path, content))
                if self.path == '/redirect-fixture':
                    self.send_response(302)
                    self.send_header('Location', parent.origin + '/redirected-fixture')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                headers = dict(self.headers)
                headers.update(Host=parent.origin.removeprefix('https://'), **{'X-Forwarded-Proto': 'https'})
                connection = http.client.HTTPConnection('127.0.0.1', parent.backend.server_address[1], timeout=4)
                try:
                    connection.request(self.command, self.path, content or None, headers)
                    response = connection.getresponse()
                    body = response.read()
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in ('server', 'date', 'connection'):
                            self.send_header(key, value)
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    connection.close()

        self.proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        self.addCleanup(self.proxy.server_close)
        self.origin = 'https://127.0.0.1:' + str(self.proxy.server_address[1])
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Atlas synthetic companion')])
        instant = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(instant - dt.timedelta(minutes=1))
                .not_valid_after(instant + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = self.root / 'public.pem', self.root / 'private.pem'
        self.ca_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        cert_path.write_text(self.ca_pem, encoding='ascii')
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        if os.name != 'nt':
            key_path.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        self.proxy.socket = context.wrap_socket(self.proxy.socket, server_side=True)
        password_path = self.root / 'server' / 'operator-auth.json'
        self.password = 'synthetic-companion-password-42'
        save_password(password_path, self.password)
        auth = HostedAuth(self.origin, password_path)
        self.backend = AtlasServer(('127.0.0.1', 0), Store(password_path.parent / 'atlas.sqlite3'), hosted=auth)
        self.backend.vulnerability.cache.ingest('osv', (FIXTURES / 'vulnerability-osv.json').read_text(encoding='utf-8'))
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.addCleanup(self.close_backend)
        self.proxy_thread = threading.Thread(target=self.proxy.serve_forever, daemon=True)
        self.proxy_thread.start()
        self.addCleanup(self.close_proxy)
        with patch('atlas.desktop.require_unprivileged'):
            self.local = DesktopRuntime(self.root / 'local').start()
        self.addCleanup(self.local.close)
        _, headers, _ = self.local_request('/')
        self.cookie = headers['Set-Cookie'].split(';')[0]
        self.nonce = self.local_request('/api/session')[2]['nonce']
        workspace = self.local.server.store.create('Private synthetic asset name', 'Private synthetic scope')
        workspace = self.local.server.store.import_file(workspace['id'], json.dumps({'format': 'atlas-evidence/1',
            'entities': [{'key': 'asset', 'label': 'Private synthetic asset name', 'addresses': ['192.0.2.99']}], 'observations': []}),
            'private-fixture.json', 'atlas', {'vantage': 'Private synthetic VPN position'})['workspace']
        self.workspace = workspace['id']
        self.subject = workspace['entities'][0]['id']

    def close_proxy(self):
        self.proxy.shutdown()
        self.proxy_thread.join(timeout=3)

    def close_backend(self):
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=3)

    def local_request(self, path, data=None, **overrides):
        connection = http.client.HTTPConnection('127.0.0.1', self.local.server.server_address[1], timeout=10)
        headers = {'Cookie': getattr(self, 'cookie', '')}
        if data is not None:
            headers.update({'Origin': self.local.url, 'Content-Type': 'application/json', 'X-Atlas-Nonce': getattr(self, 'nonce', '')})
        headers.update(overrides)
        try:
            connection.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            body = response.read()
            head = dict(response.getheaders())
            return response.status, head, json.loads(body) if head.get('Content-Type', '').startswith('application/json') else body.decode()
        finally:
            connection.close()

    def connect(self):
        result = self.local_request('/api/companion/connect', {'origin': self.origin, 'password': self.password, 'ca_pem': self.ca_pem})
        self.assertEqual(result[0], 200, result[2])
        self.assertTrue(result[2]['connected'])

    def test_real_tls_software_only_analysis_requires_explicit_save_and_preserves_inference(self):
        self.assertEqual(self.seen, [], 'Startup must not contact the companion')
        self.connect()
        config = {'workspace': self.workspace, 'subject': self.subject, 'inventory': [PACKAGE], 'allow_share': True}
        start = len(self.seen)
        bad = self.local_request('/api/companion/run', {**config, 'allow_share': False})
        self.assertEqual(bad[0], 400)
        self.assertEqual(len(self.seen), start)
        code, _, reviewed = self.local_request('/api/companion/run', config)
        self.assertEqual(code, 200, reviewed)
        self.assertTrue(reviewed['report']['results'][0]['matches'])
        outgoing = json.loads(next(body for path, body in self.seen if path == '/api/companion/analyze'))
        self.assertEqual(outgoing, {'protocol': companion.PROTOCOL, 'inventory': [PACKAGE]})
        sent = json.dumps(outgoing)
        for secret in (self.workspace, self.subject, '192.0.2.99', 'Private synthetic', self.password):
            self.assertNotIn(secret, sent)
        before = self.local.server.store.get(self.workspace)
        self.assertEqual(before['observations'], [])
        self.assertEqual(before['findings'], [])
        code, _, saved = self.local_request('/api/companion/save', {'workspace': self.workspace, 'report_id': reviewed['report_id']})
        self.assertEqual(code, 200, saved)
        observation = self.local.server.store.get(self.workspace)['observations'][-1]
        self.assertEqual(observation['subject'], self.subject)
        self.assertEqual(observation['kind'], 'advisory-analysis')
        self.assertEqual(observation['status'], 'inferred')
        self.assertEqual(observation['basis'], 'source report')
        self.assertEqual(saved['workspace']['findings'], [])
        exported = self.local.server.store.export(self.workspace)
        self.assertNotIn(self.origin, json.dumps(exported))
        self.assertNotIn('Private synthetic', json.dumps(exported))
        self.assertEqual(exported['imports'][-1]['native_context'], '[withheld]')
        self.assertEqual(self.local_request('/api/companion/save', {'workspace': self.workspace, 'report_id': reviewed['report_id']})[0], 400)
        self.assertEqual(self.local_request('/api/companion/disconnect', {})[0], 200)
        self.assertFalse(self.backend.hosted.sessions)
        self.assertEqual(self.local.server.companion.reports, {})

    def test_auth_nonce_local_remote_role_and_asset_guards_precede_outbound_requests(self):
        config = {'workspace': self.workspace, 'subject': self.subject, 'inventory': [PACKAGE], 'allow_share': True}
        for headers in ({'Cookie': ''}, {'Origin': 'https://outside.invalid'}, {'X-Atlas-Nonce': 'wrong'}):
            self.assertEqual(self.local_request('/api/companion/run', config, **headers)[0], 403)
        self.assertEqual(self.local_request('/api/companion/analyze', {'protocol': companion.PROTOCOL, 'inventory': [PACKAGE]})[0], 400)
        self.assertEqual(self.local_request('/api/companion/run', {**config, 'subject': 'other-asset'})[0], 400)
        self.assertEqual(self.local_request('/api/companion/run', config)[0], 400)
        self.assertEqual(self.seen, [])
        self.connect()
        self.assertEqual(self.local_request('/api/companion/run', {**config, 'inventory': [{**PACKAGE, 'target': '192.0.2.99'}]})[0], 400)
        self.assertFalse(any(path == '/api/companion/analyze' for path, _ in self.seen))
        client = self.local.server.companion.connections[self.local.server.session]
        for path in ('/api/companion/connect', '/api/updates/check'):
            with self.assertRaises(ImportProblem):
                companion.request_json(client['opener'], self.origin + path, {}, {'Origin': self.origin, 'X-Atlas-Nonce': client['nonce']})

    def test_untrusted_certificate_and_redirect_rejected_without_destination_request(self):
        with self.assertRaisesRegex(ImportProblem, 'TLS verification failed'):
            companion.request_json(companion.secure_opener(), self.origin + '/api/session')
        self.assertEqual(self.seen, [])
        with self.assertRaises(ImportProblem):
            companion.request_json(companion.secure_opener(self.ca_pem), self.origin + '/redirect-fixture')
        self.assertEqual([path for path, _ in self.seen], ['/redirect-fixture'])


if __name__ == '__main__':
    unittest.main()
