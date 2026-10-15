"""Terminal reviews cannot silently adopt a changed route or another operator."""
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from atlas.host_operations import plan_digest
from atlas.importers import ImportProblem
from atlas.store import Store
from atlas.terminal import Terminals


class TerminalContext(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'atlas.sqlite3')
        self.workspace = self.store.create('Synthetic terminal context', 'No target connections')['id']
        self.manager = Terminals(self.store)
        self.addCleanup(self.manager.shutdown)
        self.data = {'workspace': self.workspace, 'interface': 'tun0', 'operation': {'profile': 'http-headers', 'target': '192.0.2.20', 'url': 'https://example.test/', 'timeout': 15}}
        self.route = {'target': '192.0.2.20', 'interface': 'tun0', 'source': '192.0.2.2', 'ifindex': 10}

    def review(self):
        with patch('atlas.terminal.sys.platform', 'linux'), patch('atlas.terminal.route_to', return_value=self.route.copy()):
            result = self.manager.preview(self.data, 'owner')
        return {**self.data, 'authorized': True, 'request_id': uuid.uuid4().hex, 'digest': result['digest'], 'context_token': result['context_token']}

    def refused(self, data, workspace=None, owner='owner'):
        with patch('atlas.terminal.Terminal') as launch, patch('atlas.terminal.route_to', return_value=self.route.copy()):
            with self.assertRaises(ImportProblem):self.manager.start(workspace or self.workspace, owner, data)
            launch.assert_not_called()
        self.assertEqual(self.store.web_runs(self.workspace), [])

    def test_reviews_are_not_stored_and_expired_review_cannot_launch(self):
        data = self.review()
        self.assertNotIn(data['context_token'], json.dumps(self.store.get(self.workspace)))
        self.manager.previews[data['context_token']]['expires'] = -1
        self.refused(data)
        self.refused({**data, 'request_id': uuid.uuid4().hex})

    def test_changed_source_interface_instance_or_gateway_requires_new_review(self):
        for changed in ({'source': '192.0.2.3'}, {'ifindex': 11}, {'gateway': '192.0.2.1'}):
            data = self.review()
            self.route.update(changed)
            self.refused(data)

    def test_operator_workspace_host_and_plan_are_bound(self):
        self.refused(self.review(), owner='different-owner')
        other = self.store.create('Other synthetic assessment', 'No shared context')['id']
        self.refused(self.review(), workspace=other)
        data = self.review()
        self.manager.previews[data['context_token']]['host_id'] = 'b' * 32
        self.refused(data)
        data = self.review()
        data['operation'] = {**data['operation'], 'timeout': 20}
        data['digest'] = plan_digest({**data['operation'], 'interface': 'tun0'})
        self.refused(data)

    def test_logout_or_process_memory_loss_removes_terminal_review(self):
        data = self.review()
        self.manager.close_owner('owner')
        self.refused(data)
        data = self.review()
        self.manager = Terminals(self.store)
        self.addCleanup(self.manager.shutdown)
        self.refused(data)
