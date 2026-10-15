"""Closing a local app drains admitted requests before releasing its storage."""
import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from atlas.desktop import DesktopProblem, DesktopRuntime
from atlas.server import Handler


class ServerShutdownTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name) / 'synthetic-data'
        privilege = patch('atlas.desktop.require_unprivileged')
        privilege.start()
        self.addCleanup(privilege.stop)
        self.runtime = DesktopRuntime(self.data).start()
        self.addCleanup(self.runtime.close)
        self.server = self.runtime.server
        self.origin = self.runtime.url
        self.port = urlsplit(self.origin).port

    def post(self, path, data, results):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.request('POST', path, json.dumps(data), {
                'Content-Type': 'application/json', 'Origin': self.origin,
                'Cookie': 'atlas_session=' + self.server.session,
                'X-Atlas-Nonce': self.server.nonce,
            })
            response = connection.getresponse()
            results.append((response.status, json.loads(response.read())))
        except Exception as exc:
            results.append(exc)
        finally:
            connection.close()

    def close_in_thread(self):
        completed = threading.Event()
        errors = []

        def close():
            try:
                self.runtime.close()
            except Exception as exc:
                errors.append(exc)
            finally:
                completed.set()

        worker = threading.Thread(target=close)
        worker.start()
        self.assertTrue(self.server.closing.wait(3))
        return worker, completed, errors

    def test_pending_mutation_finishes_before_storage_lock_is_released(self):
        admitted, release, persisted = threading.Event(), threading.Event(), threading.Event()
        results, release_checks = [], []
        create = self.server.store.create
        unlock = self.runtime.guard.close

        def pending(*args, **kwargs):
            admitted.set()
            if not release.wait(5):
                raise RuntimeError('Synthetic mutation was not released.')
            result = create(*args, **kwargs)
            persisted.set()
            return result

        def checked_unlock():
            release_checks.append(persisted.is_set())
            unlock()

        with patch.object(self.server.store, 'create', side_effect=pending), \
             patch.object(self.runtime.guard, 'close', side_effect=checked_unlock):
            request = threading.Thread(target=self.post, args=(
                '/api/create', {'name': 'Synthetic shutdown persistence', 'scope': 'Fixture only'}, results))
            request.start()
            self.assertTrue(admitted.wait(3))
            closing, completed, errors = self.close_in_thread()
            try:
                self.assertFalse(completed.wait(0.1))
                with self.assertRaisesRegex(DesktopProblem, 'already open'):
                    DesktopRuntime(self.data).start()
            finally:
                release.set()
                request.join(5)
                closing.join(5)
            self.assertFalse(request.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(release_checks, [True])
            self.assertEqual(results[0][0], 200)
        with DesktopRuntime(self.data) as restarted:
            self.assertEqual([row['name'] for row in restarted.server.store.list()],
                             ['Synthetic shutdown persistence'])

    def test_body_read_before_close_cannot_dispatch_a_new_mutation_after_close(self):
        admitted, release = threading.Event(), threading.Event()
        results = []
        read_json = Handler.read_json

        def pending(handler, *args, **kwargs):
            data = read_json(handler, *args, **kwargs)
            admitted.set()
            if not release.wait(5):
                raise RuntimeError('Synthetic request body was not released.')
            return data

        with patch.object(Handler, 'read_json', pending), \
             patch.object(self.server.store, 'create', wraps=self.server.store.create) as create:
            request = threading.Thread(target=self.post, args=(
                '/api/create', {'name': 'Synthetic rejected mutation', 'scope': 'Fixture only'}, results))
            request.start()
            self.assertTrue(admitted.wait(3))
            closing, _, errors = self.close_in_thread()
            release.set()
            request.join(5)
            closing.join(5)
            self.assertFalse(request.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(results[0][0], 503)
            create.assert_not_called()

    def test_admitted_tool_start_is_registered_before_manager_shutdown(self):
        workspace = self.server.store.create('Synthetic pending tool', 'No target requests')['id']
        admitted, release = threading.Event(), threading.Event()
        results, order = [], []

        def pending(*_args, **_kwargs):
            admitted.set()
            if not release.wait(5):
                raise RuntimeError('Synthetic tool start was not released.')
            order.append('tool registered')
            return {'synthetic': True}

        with patch.object(self.server.terminals, 'start', side_effect=pending), \
             patch.object(self.server.terminals, 'shutdown', side_effect=lambda: order.append('manager stopped')):
            request = threading.Thread(target=self.post, args=(
                '/api/terminal/start', {'workspace': workspace}, results))
            request.start()
            self.assertTrue(admitted.wait(3))
            closing, completed, errors = self.close_in_thread()
            try:
                self.assertFalse(completed.wait(0.1))
                self.assertEqual(order, [])
            finally:
                release.set()
                request.join(5)
                closing.join(5)
            self.assertEqual(errors, [])
            self.assertFalse(closing.is_alive())
            self.assertEqual(order, ['tool registered', 'manager stopped'])
            self.assertEqual(results[0][0], 200)

    def test_accepted_idle_socket_is_tracked_and_has_bounded_header_reads(self):
        accepted = threading.Event()
        timeouts = []
        setup = Handler.setup

        def capture(handler):
            setup(handler)
            timeouts.append(handler.connection.gettimeout())
            accepted.set()

        with patch.object(Handler, 'setup', capture), \
             socket.create_connection(('127.0.0.1', self.port), timeout=5) as connection:
            connection.sendall(b'GET / HTTP/1.0\r\n')
            self.assertTrue(accepted.wait(3))
            self.assertEqual(timeouts, [15])
            closing, _, errors = self.close_in_thread()
            connection.sendall(f'Host: 127.0.0.1:{self.port}\r\n\r\n'.encode())
            response = b''
            while True:
                block = connection.recv(4096)
                if not block:
                    break
                response += block
            closing.join(5)
            self.assertEqual(errors, [])
            self.assertFalse(closing.is_alive())
            self.assertIn(b' 503 ', response.split(b'\r\n', 1)[0])

    def background_writer_must_finish(self, name):
        manager = getattr(self.server, name)
        stopped, release, persisted, joining = (threading.Event() for _ in range(4))
        released_after_write, join_timeouts = [], []
        unlock = self.runtime.guard.close

        def writer():
            if not stopped.wait(5) or not release.wait(5):
                return
            self.server.store.create('Synthetic final ' + name + ' evidence', 'No target requests')
            persisted.set()

        background = threading.Thread(target=writer, daemon=True)
        manager.jobs['synthetic-final-writer'] = {'thread': background, 'stop': stopped, 'workspace': 'synthetic'}
        background.start()
        join = background.join

        def slow_join(timeout=None):
            # Simulate a writer exceeding any historical timed join without
            # making the regression wait six/twelve seconds in real time.
            join_timeouts.append(timeout)
            joining.set()
            if timeout is None:
                join()

        def checked_unlock():
            released_after_write.append(persisted.is_set())
            unlock()

        with patch.object(background, 'join', side_effect=slow_join), \
             patch.object(self.runtime.guard, 'close', side_effect=checked_unlock):
            closing, completed, errors = self.close_in_thread()
            try:
                self.assertTrue(joining.wait(3))
                self.assertFalse(completed.wait(0.1))
                with self.assertRaisesRegex(DesktopProblem, 'already open'):
                    DesktopRuntime(self.data).start()
            finally:
                release.set()
                join(5)
                closing.join(5)
            self.assertEqual(errors, [])
            self.assertFalse(background.is_alive())
            self.assertFalse(closing.is_alive())
            self.assertEqual(join_timeouts, [None])
            self.assertEqual(released_after_write, [True])

    def test_cancelled_web_job_keeps_storage_until_final_writer_finishes(self):
        self.background_writer_must_finish('web')

    def test_cancelled_vulnerability_job_keeps_storage_until_final_writer_finishes(self):
        self.background_writer_must_finish('vulnerability')


if __name__ == '__main__':
    unittest.main()
