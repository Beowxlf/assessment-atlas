"""Owned local lifecycle, storage and renderer boundary checks using fixtures."""
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from atlas import desktop


class Event:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, callback):
        self.handlers.append(callback)
        return self

    def emit(self, *args):
        for callback in self.handlers:
            callback(*args)

    def connect(self, callback):
        self.handlers.append(callback)

    def disconnect(self, callback):
        self.handlers.remove(callback)


class DesktopLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'SyntheticAtlas'
        # Real refusal is tested independently; CI may run in a root container.
        self.guard = patch.object(desktop, 'require_unprivileged')
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def runtime(self, path=None):
        runtime = desktop.DesktopRuntime(path or self.path).start()
        self.addCleanup(runtime.close)
        return runtime

    def request(self, runtime, path, method='GET', body=None, **headers):
        connection = http.client.HTTPConnection('127.0.0.1', urlsplit(runtime.url).port, timeout=3)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None, headers)
            result = connection.getresponse()
            content = result.read()
            return result.status, dict(result.getheaders()), content
        finally:
            connection.close()

    def test_real_loopback_api_uses_random_port_and_existing_session_guards(self):
        runtime = self.runtime()
        self.assertEqual(runtime.server.server_address[0], '127.0.0.1')
        self.assertGreater(runtime.server.server_address[1], 0)
        status, headers, body = self.request(runtime, '/')
        self.assertEqual(status, 200)
        self.assertIn(b'Assessment Atlas', body)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertEqual(self.request(runtime, '/api/workspaces')[0], 403)
        self.assertEqual(self.request(runtime, '/', Host='outside.invalid')[0], 403)
        code, _, session = self.request(runtime, '/api/session', Cookie=cookie)
        self.assertEqual(code, 200)
        nonce = json.loads(session)['nonce']
        data = {'name': 'Synthetic desktop assessment', 'scope': 'Fixture only'}
        for changes in ({}, {'Origin': 'https://outside.invalid', 'X-Atlas-Nonce': nonce},
                        {'Origin': runtime.url, 'X-Atlas-Nonce': 'incorrect'}):
            self.assertEqual(self.request(runtime, '/api/create', 'POST', data, Cookie=cookie,
                                          **{'Content-Type': 'application/json', **changes})[0], 403)
        code, _, created = self.request(runtime, '/api/create', 'POST', data, Cookie=cookie,
                                        **{'Content-Type': 'application/json', 'Origin': runtime.url, 'X-Atlas-Nonce': nonce})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(created)['name'], data['name'])

    def test_concurrent_same_storage_refused_then_lock_released_on_close(self):
        first = self.runtime()
        with self.assertRaisesRegex(desktop.DesktopProblem, 'already open'):
            desktop.DesktopRuntime(self.path).start()
        other = self.runtime(Path(self.temp.name) / 'Other')
        self.assertNotEqual(first.url, other.url)
        port = first.server.server_address[1]
        thread = first.thread
        first.close()
        self.assertFalse(thread.is_alive())
        with socket.socket() as client:
            self.assertNotEqual(client.connect_ex(('127.0.0.1', port)), 0)
        restarted = self.runtime()
        self.assertTrue(restarted.thread.is_alive())

    def test_restart_preserves_investigation_and_loses_session_authority(self):
        runtime = self.runtime()
        store = runtime.server.store
        key = store.create('Synthetic durable assessment', 'Fixture only')['id']
        store.save_investigation(key, {'question': 'Which fixture behavior is supported?', 'next_action': 'Review again after restart'})
        run = store.start_web_run(key, 'crawl', {'url': 'http://192.0.2.1/', 'synthetic': True})
        store.update_web_run(key, run['id'], state='running')
        host = runtime.server.web.execution.host['id']
        cookie = 'atlas_session=' + runtime.server.session
        nonce = runtime.server.nonce
        runtime.close()
        reopened = self.runtime()
        self.assertEqual(reopened.server.web.execution.host['id'], host)
        retained = reopened.server.store.get(key)
        self.assertEqual(retained['investigations'][0]['next_action'], 'Review again after restart')
        self.assertEqual(retained['web_runs'][0]['state'], 'interrupted')
        self.assertNotEqual(reopened.server.nonce, nonce)
        self.assertEqual(self.request(reopened, '/api/workspaces', Cookie=cookie)[0], 403)

    def test_failed_server_initialization_releases_instance_lock(self):
        with patch.object(desktop, 'AtlasServer', side_effect=OSError('Synthetic startup failure')):
            with self.assertRaisesRegex(OSError, 'Synthetic startup'):
                desktop.DesktopRuntime(self.path).start()
        self.assertTrue(self.runtime().thread.is_alive())

    def test_shutdown_owns_existing_tool_cleanup_and_is_idempotent(self):
        runtime = self.runtime()
        managers = (runtime.server.web, runtime.server.terminals, runtime.server.vulnerability)
        with patch.object(managers[0], 'shutdown', wraps=managers[0].shutdown) as web, \
             patch.object(managers[1], 'shutdown', wraps=managers[1].shutdown) as terminal, \
             patch.object(managers[2], 'shutdown', wraps=managers[2].shutdown) as vulnerability:
            runtime.close()
            runtime.close()
            for call in (web, terminal, vulnerability):
                call.assert_called_once_with()

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions and symlink semantics')
    def test_storage_is_owner_only_and_symbolic_link_paths_are_refused(self):
        runtime = self.runtime()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(runtime.server.store.path.stat().st_mode), 0o600)
        runtime.close()
        for name in ('atlas.sqlite3', 'instance.lock'):
            file = self.path / name
            saved = file.with_suffix('.saved')
            file.rename(saved)
            file.symlink_to(saved)
            with self.assertRaisesRegex(desktop.DesktopProblem, 'unsafe'):
                desktop.DesktopRuntime(self.path).start()
            file.unlink()
            saved.rename(file)


class DesktopWindowBoundary(unittest.TestCase):
    def test_root_refused_before_creating_storage(self):
        with patch.object(os, 'geteuid', return_value=0, create=True):
            with self.assertRaisesRegex(desktop.DesktopProblem, 'without sudo'):
                desktop.require_unprivileged()

    def test_only_exact_private_origin_and_its_blob_exports_are_allowed(self):
        policy = desktop.LocalWindowPolicy('http://127.0.0.1:48291')
        for url in ('about:blank', 'http://127.0.0.1:48291/', 'http://127.0.0.1:48291/#investigations',
                    'http://127.0.0.1:48291/api/workspaces', 'blob:http://127.0.0.1:48291/synthetic-export'):
            with self.subTest(url=url):
                self.assertTrue(policy.allows(url))
        for url in ('https://outside.invalid', 'file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,fixture',
                    'http://localhost:48291/', 'http://127.0.0.1:48292/', 'http://127.0.0.1:48291@outside.invalid/',
                    'http://127.0.0.1:48291.invalid/', 'http://user@127.0.0.1:48291/', 'blob:https://outside.invalid/a',
                    'http://127.0.0.1:48291/\n', None):
            with self.subTest(url=url):
                self.assertFalse(policy.allows(url))
        for origin in ('https://127.0.0.1:2', 'http://localhost:2', 'http://127.0.0.1:2/', 'http://127.0.0.1:2#x'):
            with self.assertRaises(desktop.DesktopProblem):
                desktop.LocalWindowPolicy(origin)

    def test_webview2_cancels_external_navigation_and_popup(self):
        policy = desktop.LocalWindowPolicy('http://127.0.0.1:48291')
        native = types.SimpleNamespace(NavigationStarting=Event(), CoreWebView2InitializationCompleted=Event(),
                                        CoreWebView2=types.SimpleNamespace(NewWindowRequested=Event()))
        policy.install_edge(native)
        for url, expected in (('http://127.0.0.1:48291/', False), ('https://outside.invalid/', True), ('file:///tmp/fixture', True)):
            args = types.SimpleNamespace(Uri=url, Cancel=False)
            native.NavigationStarting.emit(native, args)
            self.assertEqual(args.Cancel, expected)
        popup = types.SimpleNamespace(Uri='https://outside.invalid/', Handled=False)
        native.CoreWebView2.NewWindowRequested.emit(native, popup)
        self.assertTrue(popup.Handled)

    def test_qt_interceptor_blocks_remote_requests_before_the_network(self):
        class Interceptor:
            def __init__(self, _parent):
                pass
        profile = types.SimpleNamespace(setUrlRequestInterceptor=lambda interceptor: active.append(interceptor))
        navigations = Event()
        native = types.SimpleNamespace(page=lambda: types.SimpleNamespace(profile=lambda: profile, navigationRequested=navigations))
        module = types.SimpleNamespace(QWebEngineUrlRequestInterceptor=Interceptor)
        active = []
        with patch.dict(sys.modules, {'qtpy.QtWebEngineCore': module}):
            desktop.LocalWindowPolicy('http://127.0.0.1:48291').install_qt(native)
        self.assertEqual(len(active), 1)
        for url, expected in (('http://127.0.0.1:48291/app.js', False), ('https://outside.invalid/', True),
                              ('file:///tmp/fixture', True), ('qrc:///qtwebchannel/qwebchannel.js', None)):
            blocked = []
            info = types.SimpleNamespace(requestUrl=lambda: types.SimpleNamespace(toString=lambda: url), block=blocked.append)
            active[0].interceptRequest(info)
            self.assertEqual(blocked, [] if expected is None else [expected])
        for url, denied in (('http://127.0.0.1:48291/', False), ('data:text/html,fixture', True), ('file:///tmp/fixture', True)):
            rejected = []
            request = types.SimpleNamespace(url=lambda: types.SimpleNamespace(toString=lambda: url), reject=lambda: rejected.append(True))
            navigations.emit(request)
            self.assertEqual(rejected, [True] if denied else [])

    def test_window_starts_blank_without_exposed_python_api_and_fails_closed(self):
        for fail in (False, True):
            window = types.SimpleNamespace(native=types.SimpleNamespace(webview=object()),
                                            events=types.SimpleNamespace(before_show=Event()), urls=[], destroyed=False)
            window.load_url = window.urls.append
            window.destroy = lambda: setattr(window, 'destroyed', True)
            settings = {}
            calls = []
            def create(*args, **kwargs):
                calls.append(kwargs)
                return window
            def start(callback, **kwargs):
                self.assertTrue(kwargs['private_mode'])
                self.assertFalse(kwargs['http_server'])
                self.assertFalse(kwargs['debug'])
                # Match pywebview's real ordering: callback thread starts before
                # native window creation; the callback must wait for the guard.
                worker = threading.Thread(target=callback)
                worker.start()
                window.events.before_show.emit()
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
            fake = types.SimpleNamespace(settings=settings, create_window=create, start=start)
            with patch.object(desktop, 'desktop_engine', return_value='edgechromium'), \
                 patch.object(desktop.importlib, 'import_module', return_value=fake), \
                 patch.object(desktop.LocalWindowPolicy, 'install_edge', side_effect=RuntimeError('fixture') if fail else None):
                if fail:
                    with self.assertRaisesRegex(desktop.DesktopProblem, 'navigation boundary'):
                        desktop.open_desktop(types.SimpleNamespace(url='http://127.0.0.1:48291'))
                    self.assertEqual(window.urls, [])
                    self.assertTrue(window.destroyed)
                else:
                    desktop.open_desktop(types.SimpleNamespace(url='http://127.0.0.1:48291'))
                    self.assertEqual(window.urls, ['http://127.0.0.1:48291'])
            self.assertEqual(calls[0]['url'], 'about:blank')
            self.assertNotIn('js_api', calls[0])
            self.assertFalse(settings['ALLOW_FILE_URLS'])
            self.assertFalse(settings['IGNORE_SSL_ERRORS'])

    def test_qt6_export_save_and_cancel_replace_the_incompatible_upstream_handler(self):
        policy = desktop.LocalWindowPolicy('http://127.0.0.1:48291')
        original = lambda download: self.fail('Qt6 must not call upstream removed setPath')
        container = types.SimpleNamespace(on_download_requested=original)
        event = Event()
        event.connect(original)
        profile = types.SimpleNamespace(downloadRequested=event)
        dialog = types.SimpleNamespace(getSaveFileName=lambda *args: ('', ''))
        module = types.SimpleNamespace(QFileDialog=dialog)
        with patch.dict(sys.modules, {'qtpy.QtWidgets': module}):
            policy.install_qt_downloads(container, profile)
        self.assertNotIn(original, event.handlers)
        for source, selected, accepted in (('blob:http://127.0.0.1:48291/export', '/tmp/synthetic-report.json', True),
                                            ('blob:http://127.0.0.1:48291/export', '', False),
                                            ('https://outside.invalid/report', '/tmp/not-written.json', False)):
            calls = []
            download = types.SimpleNamespace(url=lambda: types.SimpleNamespace(toString=lambda: source),
                suggestedFileName=lambda: '../assessment-results.json', cancel=lambda: calls.append('cancel'),
                accept=lambda: calls.append('accept'), setDownloadDirectory=lambda value: calls.append(('directory', value)),
                setDownloadFileName=lambda value: calls.append(('filename', value)))
            with patch.object(dialog, 'getSaveFileName', return_value=(selected, '')) as save:
                event.emit(download)
            if accepted:
                self.assertEqual(calls, [('directory', str(Path(selected).absolute().parent)), ('filename', 'synthetic-report.json'), 'accept'])
                self.assertEqual(Path(save.call_args.args[2]).name, 'assessment-results.json')
            else:
                self.assertEqual(calls, ['cancel'])
            if source.startswith('https:'):
                save.assert_not_called()

    def test_native_engine_rejects_disabled_sandbox_and_never_imports_gui_for_cli_help(self):
        with patch.object(desktop.sys, 'platform', 'linux'), patch.object(desktop.platform, 'freedesktop_os_release', return_value={'ID': 'debian'}), \
             patch.dict(os.environ, {'QTWEBENGINE_DISABLE_SANDBOX': '1'}):
            with self.assertRaisesRegex(desktop.DesktopProblem, 'sandbox'):
                desktop.desktop_engine()
        with patch.object(desktop.importlib, 'import_module', side_effect=AssertionError('No GUI during help')):
            with self.assertRaises(SystemExit) as exit:
                desktop.main(['--help'])
            self.assertEqual(exit.exception.code, 0)

    def test_windowed_windows_startup_failure_is_visible_without_private_paths(self):
        dialog = __import__('unittest.mock', fromlist=['Mock']).Mock()
        fake = types.SimpleNamespace(windll=types.SimpleNamespace(user32=types.SimpleNamespace(MessageBoxW=dialog)))
        with patch.object(desktop.sys, 'platform', 'win32'), patch.object(desktop.sys, 'stderr', None), \
             patch.dict(sys.modules, {'ctypes': fake}):
            self.assertTrue(desktop.report_windowed_failure(desktop.DesktopProblem('Run the desktop installer or use --browser.')))
            self.assertIn('desktop installer', dialog.call_args.args[1])
            self.assertTrue(desktop.report_windowed_failure(OSError('private-operator-data-path')))
            self.assertNotIn('private-operator-data-path', str(dialog.call_args))


if __name__ == '__main__':
    unittest.main()
