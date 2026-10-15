"""Synthetic retest custody, interpretation and restart contracts."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
import uuid

from atlas import investigations, retests
from atlas.importers import ImportProblem
from atlas.store import Store, html_report


class Retests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / 'work' / 'test-temp'
        temp_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp_root)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'atlas.sqlite3'
        self.store = Store(self.path)
        self.key = self.store.create('Synthetic retest assessment', 'Owned synthetic evidence only')['id']
        self.other = self.store.create('Separate assessment', 'No shared evidence')['id']
        for key in (self.key, self.other):
            self.add_evidence(key)
            w = self.store.get(key)
            w['records'].append({'id': uuid.uuid4().hex, 'kind': 'finding', 'title': 'PRIVATE_ORIGINAL_TITLE',
                                  'subject': w['entities'][0]['id'], 'details': 'PRIVATE_ORIGINAL_DETAILS',
                                  'status': 'open', 'severity': 'unrated', 'validation': 'operator-authored; not independently validated',
                                  'structured_evidence_refs': [{'observation_id': w['observations'][0]['id'], 'relation': 'supporting'}]})
            self.store._save(w)
        self.original = copy.deepcopy(self.store.get(self.key)['records'][0])
        self.original_observations = copy.deepcopy(self.store.get(self.key)['observations'])

    def add_evidence(self, key=None, status='observed', value='Synthetic initial response', entity='resource',
                     label='https://fixture.test/private', collected_at=None):
        bundle = {'format': 'atlas-evidence/1',
                  'entities': [{'key': entity, 'kind': 'application', 'label': label, 'addresses': []}],
                  'observations': [{'subject': entity, 'kind': 'response', 'status': status, 'basis': 'active test', 'value': value, 'collected_at': collected_at},
                                   {'subject': entity, 'kind': 'control', 'status': status, 'basis': 'active test', 'value': 'Control ' + value, 'collected_at': collected_at}]}
        return self.store.import_file(key or self.key, json.dumps(bundle), 'synthetic-evidence.json', 'atlas', {'namespace': 'synthetic-retest', 'vantage': 'owned fixture'})

    def create(self, **changes):
        data = {'original_collection': 'records', 'original_id': self.original['id'],
                'request_id': uuid.uuid4().hex, 'question': 'Does the original behavior remain in the reviewed context?', **changes}
        result = self.store.save_retest(self.key, data)
        return next(row for row in result['retests'] if row['id'] == result['retest_result_id'])

    def current(self, item):
        return next(row for row in self.store.view(self.store.get(self.key))['retests'] if row['id'] == item['id'])

    def update(self, item, **changes):
        return self.store.save_retest(self.key, {'id': item['id'], 'revision': item['revision'], **changes})

    def observed_retest(self, item):
        result = self.add_evidence(value='PRIVATE_NEW_RETEST_RESPONSE')
        observation = result['workspace']['observations'][-2]
        self.store.link_retest_evidence(self.key, {'id': item['id'], 'revision': item['revision'],
                                                  'observation_id': observation['id'], 'relation': 'supporting'})
        return self.current(item), result['import']['id']

    def test_legacy_upgrade_and_future_version_fail_safe(self):
        old = self.store.get(self.key)
        old.pop('retests'); old.pop('retests_version')
        old['future_extension'] = {'preserved': True}
        with self.store.connect() as con:
            con.execute('UPDATE workspaces SET body=? WHERE id=?', (json.dumps(old), self.key))
        upgraded = Store(self.path).get(self.key)
        self.assertEqual(upgraded['retests'], [])
        self.assertEqual(upgraded['retests_version'], 1)
        self.assertEqual({key: upgraded[key] for key in old}, old)
        with self.store.connect() as con:
            self.assertEqual(con.execute('PRAGMA user_version').fetchone()[0], 2)
            upgraded['retests_version'] = 99
            con.execute('UPDATE workspaces SET body=? WHERE id=?', (json.dumps(upgraded), self.key))
        with self.assertRaisesRegex(ImportProblem, 'Unsupported retest schema'):
            Store(self.path)
        self.assertEqual(self.store.get(self.key)['retests_version'], 99)

    def test_original_snapshot_and_baseline_are_immutable_and_durable(self):
        item = self.create(rationale='PRIVATE_RETEST_REASON', next_action='PRIVATE_RETEST_NEXT')
        self.assertEqual(item['baseline_refs'][0]['observation_id'], self.original_observations[0]['id'])
        self.assertIsNone(item['investigation_id'])
        self.assertEqual(item['outcome_label'], 'not assessed')
        for field, value in (('baseline_evidence_ids', []), ('original_id', 'other'), ('original_collection', 'findings')):
            with self.assertRaises(ImportProblem):
                self.update(item, **{field: value})
        self.store.update_record(self.key, {'id': self.original['id'], 'status': 'needs retest', 'note': 'Owner review'})
        persisted = Store(self.path).get(self.key)
        self.assertEqual(persisted['retests'][0]['original_snapshot']['status'], 'open')
        self.assertEqual(persisted['observations'], self.original_observations)
        self.assertEqual(persisted['records'][0]['status'], 'needs retest')
        self.assertNotIn('retest_result_id', persisted)
        self.assertNotIn('tests', persisted['retests'][0])

    def test_exact_creation_is_idempotent_and_request_reuse_cannot_edit(self):
        body = {'original_collection': 'records', 'original_id': self.original['id'],
                'request_id': uuid.uuid4().hex, 'question': 'A repeated deliberate retest request'}
        first = self.store.save_retest(self.key, body)
        second = self.store.save_retest(self.key, body)
        self.assertEqual(first['retest_result_id'], second['retest_result_id'])
        self.assertEqual(len(second['retests']), 1)
        with self.assertRaises(ImportProblem):
            self.store.save_retest(self.key, {**body, 'question': 'Different request content'})
        self.assertEqual(len(self.store.get(self.key)['retests']), 1)

    def test_stale_and_concurrent_edits_cannot_overwrite(self):
        item = self.create()
        barrier = threading.Barrier(2)
        outcomes = []
        def edit(reason):
            barrier.wait()
            try:
                self.update(item, rationale=reason)
                outcomes.append('saved')
            except ImportProblem:
                outcomes.append('conflict')
        threads = [threading.Thread(target=edit, args=(value,)) for value in ('One', 'Two')]
        for thread in threads: thread.start()
        for thread in threads: thread.join(10)
        self.assertCountEqual(outcomes, ['saved', 'conflict'])
        for revision in (1, True, None, '2'):
            with self.assertRaises(ImportProblem):
                self.store.save_retest(self.key, {'id': item['id'], 'revision': revision, 'rationale': 'Stale'})

    def test_strict_allowlist_and_workspace_reference_isolation(self):
        foreign = self.store.get(self.other)
        for changes in ({'original_id': foreign['records'][0]['id']}, {'original_collection': 'imports'},
                        {'baseline_evidence_ids': [foreign['observations'][0]['id']]},
                        {'auth': {'cookies': 'secret'}}, {'session_id': 'secret'}, {'headers': 'secret'},
                        {'execution_context': {}}, {'question': 'x' * 1001}, {'revision': True}, {'request_id': 'not-a-uuid'}):
            before = self.store.get(self.key)
            with self.subTest(changes=changes), self.assertRaises(ImportProblem):
                self.create(**changes)
            self.assertEqual(self.store.get(self.key), before)
        item = self.create()
        for key, relation in ((foreign['observations'][0]['id'], 'supporting'), (self.original_observations[0]['id'], 'verified')):
            with self.assertRaises(ImportProblem):
                self.store.link_retest_evidence(self.key, {'id': item['id'], 'revision': item['revision'], 'observation_id': key, 'relation': relation})
        with self.assertRaises(ImportProblem):
            self.store.save_retest(self.other, {'id': item['id'], 'revision': 1, 'rationale': 'Wrong assessment'})

    def test_no_source_absence_original_old_unrelated_or_advisory_only_resolution(self):
        item = self.create()
        for refs in ([], [{'observation_id': o['id'], 'relation': 'supporting'} for o in self.original_observations]):
            with self.assertRaises(ImportProblem):
                self.update(item, outcome='resolved', rationale='Absence is not proof', evidence_refs=refs)
        for status, entity in (('inferred', 'resource'), ('unknown', 'resource'), ('observed', 'unrelated-resource')):
            response = self.add_evidence(status=status, entity=entity, value='New ' + status + entity)
            refs = [{'observation_id': response['workspace']['observations'][-1]['id'], 'relation': 'supporting'}]
            with self.assertRaises(ImportProblem):
                self.update(item, outcome='resolved', rationale='Unsupported clean verdict', evidence_refs=refs)
        self.assertEqual(self.current(item)['outcome'], 'unknown')
        self.assertEqual(self.store.get(self.key)['records'][0], self.original)

    def test_reused_parser_key_different_target_and_historical_reimport_are_not_new_retest_proof(self):
        item = self.create()
        for kwargs in ({'label': 'https://other-fixture.test/private', 'value': 'Different target, reused parser key'},
                       {'collected_at': '2020-01-01T00:00:00Z', 'value': 'Old source imported after retest'}):
            response = self.add_evidence(**kwargs)
            with self.assertRaises(ImportProblem):
                self.update(item, outcome='resolved', rationale='Must not accept unrelated or historical proof',
                            evidence_refs=[{'observation_id': response['workspace']['observations'][-1]['id'], 'relation': 'supporting'}])

    def test_reported_outcome_needs_new_observed_evidence_rationale_and_explicit_completion(self):
        item, _ = self.observed_retest(self.create())
        with self.assertRaises(ImportProblem):
            self.update(item, outcome='resolved')
        with self.assertRaises(ImportProblem):
            self.update(item, status='complete')
        self.update(item, outcome='resolved', status='complete', rationale='PRIVATE_SCOPE_LIMIT: explicit tested control and limits')
        current = self.current(item)
        self.assertEqual(current['outcome_label'], 'reported resolved')
        self.assertIn('not independently validated', current['proof_limits'])
        reopened = Store(self.path).get(self.key)
        self.assertEqual(reopened['retests'][0]['outcome'], 'resolved')
        self.assertEqual(reopened['records'][0], self.original)
        self.assertEqual(reopened['observations'][:2], self.original_observations)
        self.assertEqual(current['original_snapshot']['validation'], self.original['validation'])

    def test_prepare_is_one_durable_investigation_without_jobs_auth_or_authority(self):
        item = self.create()
        first = self.store.prepare_retest(self.key, {'id': item['id'], 'revision': item['revision']})
        item = first['retests'][0]
        second = self.store.prepare_retest(self.key, {'id': item['id'], 'revision': item['revision']})
        self.assertEqual(first['retest_preparation']['investigation_id'], second['retest_preparation']['investigation_id'])
        self.assertEqual(len(second['investigations']), 1)
        self.assertEqual(second.get('web_runs', []), [])
        inv = second['investigations'][0]
        self.assertEqual(inv['access_mode'], 'anonymous')
        self.assertEqual(inv['access_reference'], '')
        self.assertIsNone(inv['execution_context'])
        self.assertEqual(inv['evidence_refs'], item['baseline_refs'])
        self.assertEqual(second['retest_preparation']['config'], {'url': 'https://fixture.test/private'})
        after = Store(self.path).get(self.key)
        self.assertEqual(after['retests'][0]['investigation_id'], inv['id'])
        self.assertNotIn('retest_preparation', after)

    def test_incomplete_latest_native_run_blocks_resolution_until_completed_new_evidence(self):
        item = self.create()
        response = self.store.prepare_retest(self.key, {'id': item['id'], 'revision': item['revision']})
        item, import_id = self.observed_retest(response['retests'][0])
        inv_id = item['investigation_id']
        run = self.store.start_investigation_run(self.key, 'request', {'url': 'https://fixture.test/private'}, inv_id)
        self.store.update_web_run(self.key, run['id'], state='partial', import_ids=[import_id])
        with self.assertRaisesRegex(ImportProblem, 'incomplete'):
            self.update(item, outcome='resolved', rationale='Partial results cannot establish repair')
        self.update(item, outcome='inconclusive', rationale='Session interrupted before full comparison')
        item = self.current(item)
        self.assertEqual(item['tests'][0]['snapshot']['state'], 'partial')
        restarted = Store(self.path)
        self.assertEqual(restarted.get(self.key)['retests'][0]['outcome'], 'inconclusive')
        self.store.update_web_run(self.key, run['id'], state='completed', import_ids=[])
        with self.assertRaisesRegex(ImportProblem, 'latest completed'):
            self.update(item, outcome='resolved', rationale='Unrelated evidence is not this run')
        self.store.update_web_run(self.key, run['id'], import_ids=[import_id])
        self.update(item, outcome='resolved', rationale='Completed controlled retest, bounded interpretation')
        self.assertEqual(self.current(item)['outcome'], 'resolved')

    def test_scanner_assertion_baseline_retains_unvalidated_source_and_never_closes_it(self):
        w = self.store.get(self.key)
        row = {'id': uuid.uuid4().hex, 'subject': self.original['subject'], 'title': 'Potential advisory match',
               'status': 'open', 'validation': 'source assertion; not independently validated',
               'severity': 'high', 'import_id': w['imports'][0]['id']}
        w['findings'].append(row)
        self.store._save(w)
        item = self.create(original_collection='findings', original_id=row['id'])
        self.assertEqual(len(item['baseline_refs']), 2)
        self.assertIn('source assertion', item['original_snapshot']['validation'])
        self.assertEqual(self.store.get(self.key)['findings'][0], row)

    def test_report_export_selection_redaction_and_html_escape(self):
        item, _ = self.observed_retest(self.create(question='PRIVATE_RETEST_QUESTION <script>bad()</script>',
                                                   rationale='PRIVATE_RETEST_REASON', next_action='PRIVATE_RETEST_NEXT'))
        self.update(item, outcome='still present', rationale='PRIVATE_RESULT: scope limited observation')
        default = self.store.export(self.key)
        detailed = self.store.export(self.key, True)
        for marker in ('PRIVATE_ORIGINAL_TITLE', 'PRIVATE_ORIGINAL_DETAILS', 'PRIVATE_RETEST_QUESTION',
                       'PRIVATE_RETEST_NEXT', 'PRIVATE_RESULT', 'PRIVATE_NEW_RETEST_RESPONSE'):
            self.assertNotIn(marker, json.dumps(default))
            self.assertIn(marker, json.dumps(detailed))
        self.assertNotIn('create_fingerprint', json.dumps(detailed))
        html = html_report(detailed)
        self.assertIn('Retests (operator assessments', html)
        self.assertIn('&lt;script&gt;bad()', html)
        self.assertNotIn('<script>bad()', html)
        selected = self.store.export(self.key, True, import_id=self.store.get(self.key)['imports'][0]['id'])
        self.assertEqual(selected['retests'][0]['evidence_refs'], [])
        self.assertEqual(selected['retests'][0]['export_omitted_evidence_refs_count'], 1)
        self.assertEqual(len(selected['retests'][0]['baseline_refs']), 1)


if __name__ == '__main__':
    unittest.main()
