"""Safe continuation is an inert preparation and a new independently reviewed run."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from atlas.importers import ImportProblem
from atlas.store import Store


class InvestigationResume(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'atlas.sqlite3'
        self.store = Store(self.path)
        self.workspace = self.store.create('Synthetic context', 'Owned fixtures only')['id']
        self.context = {'host_id': 'a' * 32, 'interface': 'tun0'}
        self.item = self.store.save_investigation(self.workspace, {'question': 'Can this bounded test continue?', 'execution_context': self.context})['investigations'][0]
        self.run = self.store.start_investigation_run(self.workspace, 'scanner', {
            'url': 'https://example.test/path?secret=SYNTHETIC#fragment', 'max_requests': 5,
            'body': 'SYNTHETIC_BODY', 'headers': [['Authorization', 'SYNTHETIC_TOKEN']],
            'execution_context': {'host': {'id': 'a' * 32, 'name': 'owned-server', 'platform': 'linux'},
                                  'interface': 'tun0', 'routes': [{'target': '192.0.2.20', 'interface': 'tun0', 'source': '192.0.2.2', 'secret': 'SYNTHETIC_ROUTE'}],
                                  'token': 'SYNTHETIC_PREVIEW'}}, self.item['id'])

    def prepare(self, **changes):
        item = self.store.get(self.workspace)['investigations'][0]
        return self.store.investigation_resume(self.workspace, {'id': item['id'], 'revision': item['revision'], 'run_id': self.run['id'], **changes})

    def test_restart_keeps_expectations_but_preparation_cannot_restore_authority(self):
        self.store = Store(self.path)
        original = copy.deepcopy(self.store.get(self.workspace))
        self.assertEqual(original['web_runs'][0]['state'], 'interrupted')
        self.assertEqual(original['investigations'][0]['execution_context'], self.context)
        prepared = self.prepare()['resume_preparation']
        self.assertEqual(prepared['resumes_run_id'], self.run['id'])
        self.assertEqual(prepared['config']['url'], 'https://example.test/path')
        self.assertEqual(prepared['config']['max_requests'], 5)
        self.assertEqual(self.store.get(self.workspace), original)
        serialized = json.dumps(prepared)
        for secret in ('SYNTHETIC', 'authorized', 'context_token', 'auth', 'session_id', 'headers', 'body'):
            self.assertNotIn('"' + secret + '"', serialized)
        self.assertNotIn('SYNTHETIC', serialized)

    def test_new_run_preserves_original_and_links_source_atomically(self):
        self.store.update_web_run(self.workspace, self.run['id'], state='partial', reason='Route changed', requests=2)
        original = copy.deepcopy(self.store.get(self.workspace)['web_runs'][0])
        new = self.store.start_investigation_run(self.workspace, 'scanner', {'url': 'https://example.test/reviewed'}, self.item['id'], resumes_run_id=self.run['id'])
        self.assertNotEqual(new['id'], self.run['id'])
        self.assertEqual(new['plan']['resumes_run_id'], self.run['id'])
        self.assertEqual(self.store.get(self.workspace)['web_runs'][0], original)
        self.assertEqual(len(self.store.get(self.workspace)['investigations'][0]['tests']), 2)

    def test_active_completed_foreign_and_stale_sources_are_refused_without_mutation(self):
        for state in ('queued', 'running', 'completed'):
            self.store.update_web_run(self.workspace, self.run['id'], state=state)
            before = copy.deepcopy(self.store.get(self.workspace))
            with self.assertRaises(ImportProblem):self.prepare()
            self.assertEqual(before, self.store.get(self.workspace))
        self.store.update_web_run(self.workspace, self.run['id'], state='cancelled')
        for fields in ({'revision': 1}, {'run_id': 'b' * 32}, {'auth': {'token': 'SYNTHETIC'}}):
            with self.assertRaises(ImportProblem):self.prepare(**fields)
        other = self.store.save_investigation(self.workspace, {'question': 'Separate question'})['investigations'][-1]
        with self.assertRaises(ImportProblem):
            self.store.start_investigation_run(self.workspace, 'scanner', {}, other['id'], resumes_run_id=self.run['id'])
        self.assertEqual(len(self.store.web_runs(self.workspace)), 1)

    def test_context_snapshots_and_default_exports_exclude_capabilities(self):
        view = Store.view(self.store.get(self.workspace))['investigations'][0]['tests'][0]['snapshot']
        self.assertEqual(view['execution_context']['host']['name'], 'owned-server')
        self.assertNotIn('SYNTHETIC', json.dumps(view))
        exported = self.store.export(self.workspace)
        self.assertEqual(exported['investigations'][0]['execution_context'], '[withheld]')
        self.assertEqual(exported['investigations'][0]['tests'][0]['snapshot']['execution_context'], '[withheld]')
        self.assertNotIn('owned-server', json.dumps(exported))

    def test_caller_cannot_save_measured_routes_or_session_as_context(self):
        for context in ({**self.context, 'routes': []}, {**self.context, 'token': 'SYNTHETIC'}, {'host_id': 'bad', 'interface': 'tun0'}, {**self.context, 'interface': 'tun0;id'}):
            with self.assertRaises(ImportProblem):
                self.store.save_investigation(self.workspace, {'question': 'Invalid context', 'execution_context': context})

    def test_legacy_investigation_edit_is_additive(self):
        workspace = self.store.get(self.workspace)
        workspace['investigations'][0].pop('execution_context')
        before = copy.deepcopy(workspace['investigations'][0])
        self.store._save(workspace)
        self.store.save_investigation(self.workspace, {'id': before['id'], 'revision': before['revision'], 'next_action': 'Review actual host'})
        updated = self.store.get(self.workspace)['investigations'][0]
        self.assertEqual(updated['id'], before['id'])
        self.assertEqual(updated['tests'], before['tests'])
        self.assertIsNone(updated.get('execution_context'))

    def test_resume_preserves_narrow_path_and_exclusions_without_network_activity(self):
        self.store.update_web_run(self.workspace, self.run['id'], state='partial', plan={
            'url': 'https://example.test/app/record?secret=SYNTHETIC',
            'origins': {'https://example.test': '/app'}, 'excluded_paths': ['/app/logout']})
        with patch('socket.getaddrinfo', side_effect=AssertionError('Resume must not resolve names')):
            prepared = self.prepare()['resume_preparation']['config']
        self.assertEqual(prepared['path_prefix'], '/app')
        self.assertEqual(prepared['exclude_paths'], ['/app/logout'])
        self.assertEqual(prepared['extra_origins'], [])
        from atlas.web_transport import Scope
        scoped = Scope({**prepared, 'authorized': True}, resolve=False)
        for url in ('https://example.test/elsewhere', 'https://example.test/app/logout'):
            with self.assertRaises(ImportProblem):scoped.check(url)
        scoped.check('https://example.test/app/record')

    def test_default_export_withholds_top_level_terminal_route_and_all_supported_routes_survive_snapshot(self):
        routes = [{'target': '192.0.2.' + str(index), 'interface': 'tun0', 'source': '192.0.2.2', 'ifindex': 10, 'table': 254} for index in range(1, 81)]
        self.store.update_web_run(self.workspace, self.run['id'], route={'target': 'SYNTHETIC_PRIVATE_ROUTE'},
            execution_context={'host_name': 'SYNTHETIC_PRIVATE_HOST'}, plan={'execution_context': {'routes': routes}})
        current = Store.view(self.store.get(self.workspace))
        # Refreshing an explicitly linked snapshot preserves the complete bounded proof.
        item = current['investigations'][0]
        self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': item['revision'], 'run_id': self.run['id']})
        snapshot = Store.view(self.store.get(self.workspace))['investigations'][0]['tests'][0]['snapshot']
        self.assertEqual(snapshot['execution_context']['routes'], routes)
        exported = self.store.export(self.workspace)
        self.assertEqual(exported['web_runs'][0]['route'], '[withheld]')
        self.assertNotIn('SYNTHETIC_PRIVATE', json.dumps(exported))
