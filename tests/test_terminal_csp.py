"""Per-document style authority must not weaken script or ordinary inline CSP."""
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest

from atlas.hosted_auth import HostedAuth, save_password
from atlas.server import AtlasServer
from atlas.store import Store


class TerminalCSP(unittest.TestCase):
    @contextmanager
    def application(self, hosted=False):
        root = Path(__file__).resolve().parents[1] / 'work' / 'test-temp'
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as folder:
            data = Path(folder)
            auth = None
            if hosted:
                save_password(data / 'operator-auth.json', 'synthetic-csp-password')
                auth = HostedAuth('https://atlas.csp.test', data / 'operator-auth.json')
            server = AtlasServer(('127.0.0.1', 0), Store(data / 'atlas.sqlite3'), hosted=auth)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield server
            finally:
                server.shutdown()
                server.server_close()
                thread.join(5)

    def request(self, server, path='/', data=None, cookie=''):
        connection = http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=5)
        headers = {'Cookie': cookie}
        if server.hosted:
            headers.update(Host='atlas.csp.test', Origin='https://atlas.csp.test')
            headers['X-Forwarded-Proto'] = 'https'
        if data is not None:
            headers['Content-Type'] = 'application/json'
        try:
            connection.request('POST' if data is not None else 'GET', path, json.dumps(data) if data is not None else None, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode()
        finally:
            connection.close()

    def document_nonce(self, headers, text):
        policy = headers['Content-Security-Policy']
        self.assertNotIn('unsafe-inline', policy)
        self.assertNotIn('unsafe-eval', policy)
        self.assertIn("script-src 'self';", policy)
        nonce = re.search(r'<meta name="atlas-style-nonce" content="([A-Za-z0-9_-]{32})">', text)
        self.assertIsNotNone(nonce)
        self.assertIn("style-src 'self' 'nonce-" + nonce[1] + "';", policy)
        self.assertEqual(policy.count('nonce-'), 1)
        self.assertNotIn('__ATLAS_STYLE_NONCE__', text)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        return nonce[1]

    def test_each_index_has_unique_style_only_nonce_without_granting_other_responses(self):
        with self.application() as server:
            _, first_headers, first_html = self.request(server)
            _, second_headers, second_html = self.request(server)
            first = self.document_nonce(first_headers, first_html)
            second = self.document_nonce(second_headers, second_html)
            self.assertNotEqual(first, second)
            self.assertNotEqual(first, server.nonce)
            self.assertNotEqual(first, server.session)
            _, headers, _ = self.request(server, '/operator-console.js')
            self.assertNotIn('nonce-', headers['Content-Security-Policy'])
            self.assertIn("style-src 'self';", headers['Content-Security-Policy'])

    def test_hosted_login_stays_strict_and_only_authenticated_index_gets_style_nonce(self):
        with self.application(hosted=True) as server:
            _, headers, login_html = self.request(server)
            self.assertNotIn('nonce-', headers['Content-Security-Policy'])
            self.assertNotIn('atlas-style-nonce', login_html)
            code, headers, _ = self.request(server, '/api/login', {'password': 'synthetic-csp-password'})
            self.assertEqual(code, 200)
            cookie = headers['Set-Cookie'].split(';')[0]
            code, headers, index = self.request(server, cookie=cookie)
            self.assertEqual(code, 200)
            self.document_nonce(headers, index)


if __name__ == '__main__':
    unittest.main()
