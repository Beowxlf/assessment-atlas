"""Synthetic persistence and trust-boundary contracts for investigations."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest

from atlas import investigations
from atlas.importers import ImportProblem
from atlas.store import Store, html_report


class Investigations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'atlas.sqlite3'
        self.store = Store(self.path)
        self.workspace = self.store.create('Synthetic investigation', 'Owned fixtures only')['id']
        self.other = self.store.create('Synthetic separate workspace', 'No shared identity')['id']
        self.seed = {'format': 'atlas-evidence/1', 'entities': [
            {'key': 'a', 'label': 'Synthetic service', 'kind': 'device', 'addresses': ['192.0.2.20']},
            {'key': 'b', 'label': 'Separate service', 'kind': 'device', 'addresses': ['192.0.2.21']}],
            'observations': [
                {'subject': 'a', 'kind': 'response', 'status': 'observed', 'basis': 'active test', 'value': 'Synthetic public response'},
                {'subject': 'a', 'kind': 'control', 'status': 'unknown', 'basis': 'manual', 'value': 'Synthetic counter evidence'},
                {'subject': 'b', 'kind': 'separate', 'status': 'observed', 'basis': 'manual', 'value': 'Separate observation'}]}
        for workspace in (self.workspace, self.other):
            self.store.import_file(workspace, json.dumps(self.seed), 'synthetic.json', 'atlas', {})
        w = self.store.get(self.workspace)
        self.subject = w['entities'][0]['id']
        self.second_subject = w['entities'][1]['id']
        self.obs = [o['id'] for o in w['observations']]

    def create(self, **changes):
        response = self.store.save_investigation(self.workspace, {'question': 'What does this response establish?', 'subject': self.subject, **changes})
        return next(i for i in response['investigations'] if i['id'] == response['investigation_result_id'])

    def current(self, key):
        return next(i for i in Store.view(self.store.get(self.workspace))['investigations'] if i['id'] == key)

    def linked(self):
        item = self.create()
        self.store.link_investigation_evidence(self.workspace, {'id': item['id'], 'revision': item['revision'], 'observation_id': self.obs[0], 'relation': 'supporting'})
        return self.current(item['id'])

    def test_additive_legacy_upgrade_preserves_every_existing_value_and_id(self):
        w = self.store.get(self.workspace)
        w.pop('investigations'); w.pop('investigations_version')
        w['future_metadata'] = {'untouched': True}
        with self.store.connect() as con:
            con.execute('UPDATE workspaces SET body=? WHERE id=?', (json.dumps(w), self.workspace))
        reopened = Store(self.path).get(self.workspace)
        self.assertEqual(reopened['investigations_version'], 1)
        self.assertEqual(reopened['investigations'], [])
        for key, value in w.items():
            self.assertEqual(reopened[key], value, key)
        with self.store.connect() as con:
            self.assertEqual(con.execute('PRAGMA user_version').fetchone()[0], 2)

    def test_durable_resume_and_response_id_is_never_persisted(self):
        item = self.create(objective='Review access boundary', rationale='A negative result is useful.', next_action='Compare the legitimate control', access_mode='authenticated', access_role='Lab user', access_reference='ref:account-a')
        self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': 1, 'status': 'blocked', 'decision': 'inconclusive'})
        reopened = Store(self.path).get(self.workspace)
        retained = reopened['investigations'][0]
        self.assertEqual(retained['question'], item['question'])
        self.assertEqual(retained['revision'], 2)
        self.assertEqual(retained['status'], 'blocked')
        self.assertEqual(retained['decision'], 'inconclusive')
        self.assertEqual(retained['access_reference'], 'ref:account-a')
        self.assertNotIn('investigation_result_id', reopened)
        self.assertNotIn('investigation_result_id', self.store.export(self.workspace, True))
        self.assertEqual(len(retained['events']), 2)

    def test_reference_validation_and_strict_secret_field_rejection_are_atomic(self):
        foreign = self.store.get(self.other)
        for data in ({'subject': foreign['entities'][0]['id']}, {'access_mode': 'authenticated', 'access_reference': 'Bearer synthetic-token'},
                     {'auth': {'cookies': 'synthetic'}}, {'session_id': 'synthetic-session'}, {'headers': []}, {'question': 'x' * 1001}, {'revision': True}):
            before = copy.deepcopy(self.store.get(self.workspace))
            with self.subTest(data=data), self.assertRaises(ImportProblem):
                self.store.save_investigation(self.workspace, {'question': 'Synthetic question', **data})
            self.assertEqual(self.store.get(self.workspace), before)
        item = self.create()
        for key, relation in ((foreign['observations'][0]['id'], 'supporting'), (self.obs[0], 'validated')):
            with self.assertRaises(ImportProblem):
                self.store.link_investigation_evidence(self.workspace, {'id': item['id'], 'revision': 1, 'observation_id': key, 'relation': relation})
        self.assertEqual(self.current(item['id'])['evidence_refs'], [])

    def test_optimistic_revision_rejects_a_stale_editor(self):
        item = self.create()
        self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': 1, 'rationale': 'First editor saved this.'})
        for revision in (1, None, True, '2'):
            with self.subTest(revision=revision), self.assertRaises(ImportProblem):
                self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': revision, 'rationale': 'Stale editor'})
        self.assertEqual(self.current(item['id'])['rationale'], 'First editor saved this.')

    def test_concurrent_updates_allow_one_winner(self):
        item = self.create()
        barrier = threading.Barrier(2)
        outcomes = []
        def save(value):
            barrier.wait()
            try:
                self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': 1, 'rationale': value})
                outcomes.append('saved')
            except ImportProblem:
                outcomes.append('conflict')
        threads = [threading.Thread(target=save, args=(str(i),)) for i in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        self.assertEqual(sorted(outcomes), ['conflict', 'saved'])
        self.assertEqual(self.current(item['id'])['revision'], 2)

    def test_server_derived_snapshot_excludes_all_arbitrary_request_state(self):
        item = self.create()
        run = self.store.start_web_run(self.workspace, 'scanner', {
            'url': 'https://user:private@example.test/path?token=synthetic-query#fragment',
            'origins': ['https://example.test'], 'vantage': 'Synthetic server', 'max_requests': 4,
            'headers': {'Authorization': 'Bearer synthetic-header'}, 'cookies': 'synthetic-cookie',
            'auth': {'password': 'synthetic-password'}, 'session_id': 'synthetic-session', 'body': 'synthetic-body',
            'ca_private_key': 'synthetic-key', 'unknown': 'synthetic-unknown'})
        with self.assertRaises(ImportProblem):
            self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': 1, 'run_id': run['id'], 'config': {'token': 'synthetic'}})
        self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': 1, 'run_id': run['id']})
        snapshot = self.current(item['id'])['tests'][0]['snapshot']
        self.assertEqual(snapshot['context']['url'], 'https://example.test/path')
        serialized = json.dumps(snapshot)
        for secret in ('synthetic-header', 'synthetic-cookie', 'synthetic-password', 'synthetic-session', 'synthetic-body', 'synthetic-key', 'synthetic-unknown', 'synthetic-query', 'user:private'):
            self.assertNotIn(secret, serialized)
        self.assertEqual(snapshot['state'], 'queued')
        self.assertEqual(snapshot['completeness'], 'in progress')

    def test_native_run_state_updates_and_restart_do_not_become_negative_results(self):
        item = self.create()
        run = self.store.start_web_run(self.workspace, 'crawl', {'url': 'http://example.test/', 'max_requests': 2})
        self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': 1, 'run_id': run['id']})
        self.store.update_web_run(self.workspace, run['id'], state='running', requests=1)
        Store(self.path)
        snapshot = self.current(item['id'])['tests'][0]['snapshot']
        self.assertEqual(snapshot['state'], 'interrupted')
        self.assertEqual(snapshot['completeness'], 'incomplete')
        self.assertEqual(snapshot['requests'], 1)
        self.assertEqual(self.current(item['id'])['decision'], 'undecided')
        for state in ('partial', 'failed', 'stopped', 'completed'):
            self.store.update_web_run(self.workspace, run['id'], state=state)
            retained = self.current(item['id'])
            self.assertEqual(retained['tests'][0]['snapshot']['state'], state)
            self.assertEqual(retained['decision'], 'undecided')
            self.assertEqual(retained['status'], 'open')

    def test_foreign_runs_and_evidence_arrays_are_rejected(self):
        item = self.create()
        foreign = self.store.start_web_run(self.other, 'crawl', {'url': 'http://example.test/'})
        with self.assertRaises(ImportProblem):
            self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': 1, 'run_id': foreign['id']})
        for refs in ([{'observation_id': self.obs[0], 'relation': 'supporting'}] * 201,
                     [{'observation_id': self.obs[0], 'relation': 'supporting'}, {'observation_id': self.obs[0], 'relation': 'context'}]):
            with self.assertRaises(ImportProblem):
                self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': 1, 'evidence_refs': refs})

    def test_finding_handoff_preserves_claim_limits_and_is_idempotent(self):
        item = self.linked()
        request = {'id': item['id'], 'revision': item['revision'], 'title': 'Synthetic concern', 'details': 'This observed behavior requires impact validation.', 'severity': 'low'}
        response = self.store.investigation_finding(self.workspace, request)
        self.store.investigation_finding(self.workspace, request)
        findings = [r for r in self.store.get(self.workspace)['records'] if r['kind'] == 'finding']
        self.assertEqual(len(findings), 1)
        self.assertEqual(response['investigation_result_id'], item['id'])
        record = findings[0]
        self.assertEqual(record['investigation_id'], item['id'])
        self.assertEqual(record['structured_evidence_refs'], item['evidence_refs'])
        self.assertEqual(record['status'], 'open')
        self.assertIn('not independently validated', record['validation'])
        self.assertIn('does not establish', record['proof_limits'])
        self.assertEqual(self.current(item['id'])['decision'], 'undecided')

    def test_finding_requires_linked_selected_evidence(self):
        item = self.create()
        request = {'id': item['id'], 'revision': 1, 'title': 'Synthetic concern', 'details': 'Review required.'}
        with self.assertRaises(ImportProblem): self.store.investigation_finding(self.workspace, request)
        self.store.link_investigation_evidence(self.workspace, {'id': item['id'], 'revision': 1, 'observation_id': self.obs[0], 'relation': 'contradicting'})
        request['revision'] = 2
        for selected in ([], [self.obs[1]], [self.obs[0], self.obs[0]]):
            with self.assertRaises(ImportProblem):
                self.store.investigation_finding(self.workspace, {**request, 'evidence_ids': selected})
        self.store.investigation_finding(self.workspace, {**request, 'evidence_ids': [self.obs[0]]})
        record = self.store.get(self.workspace)['records'][0]
        self.assertEqual(record['structured_evidence_refs'][0]['relation'], 'contradicting')

    def test_next_question_preserves_declared_access_context_but_no_live_session(self):
        parent = self.create(access_mode='authenticated', access_role='Test owner', access_reference='ref:account-a')
        response = self.store.investigation_next(self.workspace, {'id': parent['id'], 'revision': 1, 'question': 'What remains unproven?'})
        child = self.current(response['investigation_result_id'])
        self.assertEqual(child['access_mode'], 'authenticated')
        self.assertEqual(child['access_role'], 'Test owner')
        self.assertEqual(child['access_reference'], 'ref:account-a')
        self.assertNotIn('session_id', child)
        self.assertEqual(child['tests'], [])
        self.assertEqual(self.current(parent['id'])['next_investigation_ids'], [child['id']])
        self.assertEqual(child['subject'], parent['subject'])

    def test_filtered_export_has_no_dangling_investigation_or_finding_evidence(self):
        item = self.create(evidence_refs=[{'observation_id': self.obs[0], 'relation': 'supporting'}, {'observation_id': self.obs[1], 'relation': 'contradicting'}])
        self.store.investigation_finding(self.workspace, {'id': item['id'], 'revision': 1, 'title': 'Synthetic concern', 'details': 'Both controls matter.'})
        item = self.current(item['id'])
        following = self.store.investigation_next(self.workspace, {'id': item['id'], 'revision': item['revision'], 'question': 'Separate identity question', 'subject': self.second_subject})
        omitted_id = following['investigation_result_id']
        run = self.store.start_investigation_run(self.workspace, 'crawl', {'url': 'https://example.test/'}, omitted_id)
        exported = self.store.export(self.workspace, identifiers=True, kind='response')
        retained = exported['investigations'][0]
        self.assertEqual(len(exported['investigations']), 1)
        self.assertEqual(retained['next_investigation_ids'], [])
        self.assertEqual(retained['export_omitted_evidence_count'], 1)
        existing = {o['id'] for o in exported['observations'] + exported['context_observations']}
        self.assertTrue(all(r['observation_id'] in existing for r in retained['evidence_refs']))
        finding = exported['records'][0]
        self.assertEqual(finding['structured_evidence_refs'], retained['evidence_refs'])
        self.assertNotIn(self.obs[1], finding['evidence_refs'])
        self.assertIsNone(next(r for r in exported['web_runs'] if r['id'] == run['id'])['plan']['investigation_id'])
        self.assertTrue(all(h.get('investigation_id') != omitted_id for h in exported['history']))

    def test_redacted_export_hides_all_new_free_text_and_report_escapes_markup(self):
        marker = 'SYNTHETIC-PRIVATE-MARKER'
        item = self.create(question='<script>' + marker + '</script>', objective=marker, rationale=marker,
                           next_action=marker, access_mode='authenticated', access_role=marker, access_reference='ref:' + marker)
        self.store.link_investigation_evidence(self.workspace, {'id': item['id'], 'revision': 1, 'observation_id': self.obs[0], 'relation': 'supporting'})
        self.store.investigation_finding(self.workspace, {'id': item['id'], 'revision': 2, 'title': marker, 'details': marker})
        run = self.store.start_web_run(self.workspace, 'crawl', {'url': 'https://example.test/' + marker, 'vantage': marker})
        self.store.link_investigation_run(self.workspace, {'id': item['id'], 'revision': 3, 'run_id': run['id']})
        redacted = self.store.export(self.workspace)
        self.assertNotIn(marker, json.dumps(redacted))
        self.assertNotIn(marker, html_report(redacted))
        full = html_report(self.store.export(self.workspace, True))
        self.assertIn('Investigations and decisions', full)
        self.assertIn('&lt;script&gt;', full)
        self.assertNotIn('<script>' + marker, full)
        self.assertIn('not independently validated', json.dumps(self.store.get(self.workspace)))

    def test_collection_limits_fail_without_partial_mutation(self):
        item = self.create()
        w = self.store.get(self.workspace)
        w['investigations'][0]['events'] = [{'action': 'synthetic'}] * investigations.MAX_EVENTS
        self.store._save(w)
        with self.assertRaises(ImportProblem):
            self.store.save_investigation(self.workspace, {'id': item['id'], 'revision': 1, 'rationale': 'Must not persist'})
        self.assertEqual(self.store.get(self.workspace), w)

    def test_atomic_start_cannot_leave_a_queued_orphan_when_link_limits_fail(self):
        item = self.create()
        w = self.store.get(self.workspace)
        w['investigations'][0]['events'] = [{'action': 'synthetic'}] * investigations.MAX_EVENTS
        self.store._save(w)
        with self.assertRaises(ImportProblem):
            self.store.start_investigation_run(self.workspace, 'crawl', {'url': 'http://example.test/'}, item['id'])
        self.assertEqual(self.store.get(self.workspace), w)

    def test_historical_authentication_summary_is_allowlisted_and_never_a_session(self):
        item = self.create(access_mode='authenticated', access_reference='ref:account-a')
        run = self.store.start_investigation_run(self.workspace, 'scanner', {'authentication': {
            'mode': 'transient origin-bound session', 'check_url': 'https://example.test/SYNTHETIC-GUARD',
            'success_text': 'SYNTHETIC-MARKER', 'cookies': 'SYNTHETIC-COOKIE'}}, item['id'])
        self.store.update_web_run(self.workspace, run['id'], state='partial', authentication={
            'mode': 'session credentials', 'session_verified': True, 'generation': 2,
            'headers': ['SYNTHETIC-HEADER'], 'token': 'SYNTHETIC-TOKEN'})
        snapshot = self.current(item['id'])['tests'][0]['snapshot']
        self.assertEqual(snapshot['authentication'], {'mode': 'session credentials', 'session_verified': True, 'generation': 2})
        for value in ('SYNTHETIC-GUARD', 'SYNTHETIC-MARKER', 'SYNTHETIC-COOKIE', 'SYNTHETIC-HEADER', 'SYNTHETIC-TOKEN'):
            self.assertNotIn(value, json.dumps(snapshot))
        self.assertEqual(snapshot['completeness'], 'incomplete')


if __name__ == '__main__':
    unittest.main()
