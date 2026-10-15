"""Operator-host desktop shell with an owned, private loopback Atlas runtime.

The native window is only a view of the existing HTTP application. It receives
no Python API, filesystem bridge or remote execution endpoint. Collectors run
in this process and therefore use this host's reviewed routes and VPN.
"""
import argparse
import importlib
import os
from pathlib import Path
import platform
import stat
import sys
import threading
from urllib.parse import urlsplit
import webbrowser

from . import __version__
from .importers import ImportProblem
from .server import AtlasServer
from .store import Store


class DesktopProblem(ImportProblem):
    """An actionable startup failure without engagement or credential details."""


def default_data_dir():
    """Reuse the existing local data location, independently of install updates."""
    if sys.platform == 'win32':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'AssessmentAtlas'
    if sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'AssessmentAtlas'
    configured = os.environ.get('XDG_DATA_HOME', '')
    root = Path(configured) if configured and Path(configured).is_absolute() else Path.home() / '.local' / 'share'
    return root / 'AssessmentAtlas'


def require_unprivileged():
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        raise DesktopProblem('Start Assessment Atlas as your ordinary desktop user, without sudo. Root execution is refused.')


class InstanceLock:
    """Use the same OS lock as atlas.server; a stale lock file is harmless."""
    def __init__(self, directory):
        self.directory = Path(directory).expanduser().absolute()
        self.file = None

    def acquire(self):
        if self.file is not None:
            raise DesktopProblem('This desktop runtime already owns its data folder.')
        if self.directory.is_symlink():
            raise DesktopProblem('Choose a real local data folder rather than a symbolic link.')
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != 'nt':
            if self.directory.stat().st_uid != os.geteuid():
                raise DesktopProblem('The data folder must belong to the current desktop user.')
            self.directory.chmod(0o700)
        for name in ('instance.lock', 'atlas.sqlite3'):
            path = self.directory / name
            if path.is_symlink() or path.exists() and not path.is_file():
                raise DesktopProblem('The data folder contains an unsafe lock or database path. Choose a protected local data folder.')
        descriptor = os.open(self.directory / 'instance.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        guard = os.fdopen(descriptor, 'r+b')
        try:
            if not stat.S_ISREG(os.fstat(guard.fileno()).st_mode):
                raise DesktopProblem('The instance lock must be a regular local file.')
            if os.name == 'nt':
                import msvcrt
                guard.seek(0)
                if not guard.read(1):
                    guard.seek(0)
                    guard.write(b'0')
                    guard.flush()
                guard.seek(0)
                msvcrt.locking(guard.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fchmod(guard.fileno(), 0o600)
        except OSError:
            guard.close()
            raise DesktopProblem('This data folder is already open in another Assessment Atlas process. Use that instance or a separate --data-dir.') from None
        except Exception:
            guard.close()
            raise
        self.file = guard
        return self

    def close(self):
        if self.file is not None:
            self.file.close()  # Closing the descriptor releases the OS lock.
            self.file = None


class DesktopRuntime:
    """Own all native jobs, transient authority, listener and storage lock."""
    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self.guard = InstanceLock(self.data_dir)
        self.server = None
        self.thread = None
        self.url = None

    def start(self):
        require_unprivileged()
        if self.server is not None:
            raise DesktopProblem('This desktop runtime is already running.')
        self.guard.acquire()
        try:
            store = Store(self.guard.directory / 'atlas.sqlite3')
            if os.name != 'nt':
                store.path.chmod(0o600)
            self.server = AtlasServer(('127.0.0.1', 0), store)
            self.server.desktop = True
            self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.05}, name='atlas-desktop-runtime', daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise
        return self

    def close(self):
        server, thread = self.server, self.thread
        self.server, self.thread = None, None
        try:
            if server is not None:
                try:
                    if thread is not None and thread.is_alive():
                        server.shutdown()
                finally:
                    server.server_close()
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=5)
        finally:
            self.guard.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()


class LocalWindowPolicy:
    """The shell cannot become a browser for a target or a local file.

    Qt enforces this before requests leave the renderer. WebView2 cancels main
    navigation and popups. The UI's existing CSP still constrains subresources,
    API origins and frames. Blob downloads are explicitly allowed for reports.
    """
    def __init__(self, origin):
        parsed = urlsplit(origin)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port or parsed.path or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise DesktopProblem('The desktop window requires its own exact loopback origin.')
        self.origin = origin
        self.references = []

    def allows(self, url):
        if not isinstance(url, str) or any(ord(c) < 32 for c in url):
            return False
        if url == 'about:blank':
            return True
        if url.startswith('blob:'):
            return self.allows(url[5:]) and url[5:].startswith(self.origin + '/')
        try:
            parsed = urlsplit(url)
            base = urlsplit(self.origin)
            return parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port == base.port and parsed.username is None and parsed.password is None and parsed.netloc == base.netloc
        except (ValueError, TypeError):
            return False

    def edge_navigation(self, _sender, args):
        if not self.allows(str(args.Uri)):
            args.Cancel = True

    @staticmethod
    def edge_popup(_sender, args):
        args.Handled = True

    def install_edge(self, native):
        native.NavigationStarting += self.edge_navigation
        # CoreWebView2 can finish initializing after before_show. Initialization
        # itself only loads about:blank; the app URL is loaded after the hook.
        def ready(_sender=None, args=None):
            if args is not None and not args.IsSuccess:
                return
            core = native.CoreWebView2
            if core is not None:
                core.NewWindowRequested += self.edge_popup
        native.CoreWebView2InitializationCompleted += ready
        ready()
        self.references.extend((native, ready))

    def install_qt(self, native, container=None):
        # qtpy follows the renderer selected by pywebview, avoiding a second Qt
        # binding in the same process. No dependency is imported in browser mode.
        from qtpy.QtWebEngineCore import QWebEngineUrlRequestInterceptor
        policy = self

        class Interceptor(QWebEngineUrlRequestInterceptor):
            def interceptRequest(self, info):
                url = info.requestUrl().toString()
                # This is Qt's built-in local channel script, not filesystem or
                # network access; pywebview needs it even without an exposed API.
                if url == 'qrc:///qtwebchannel/qwebchannel.js':
                    return
                info.block(not policy.allows(url))

        page = native.page()
        profile = page.profile()
        interceptor = Interceptor(profile)
        profile.setUrlRequestInterceptor(interceptor)

        def navigation(request):
            if not self.allows(request.url().toString()):
                request.reject()

        # Some non-network schemes need not reach a URL request interceptor.
        # Qt 6's navigation decision closes that boundary before document load.
        page.navigationRequested.connect(navigation)
        self.references.extend((profile, interceptor, page, navigation))
        if container is not None:
            self.install_qt_downloads(container, profile)

    def install_qt_downloads(self, container, profile):
        """Use Qt 6's public download API; pywebview 6.2.1 uses removed setPath.

        An export always uses an operator Save dialog, and cancel leaves no
        download accepted. The source must still belong to this runtime.
        """
        from qtpy.QtWidgets import QFileDialog
        profile.downloadRequested.disconnect(container.on_download_requested)

        def save(download):
            try:
                if not self.allows(download.url().toString()):
                    download.cancel()
                    return
                suggested = download.suggestedFileName().replace('\\', '/').rsplit('/', 1)[-1]
                if suggested in ('', '.', '..'):
                    suggested = 'assessment-export'
                selected, _ = QFileDialog.getSaveFileName(container, 'Save assessment export',
                                                         str(Path.home() / suggested), 'All files (*)')
                if not selected:
                    download.cancel()
                    return
                path = Path(selected).absolute()
                download.setDownloadDirectory(str(path.parent))
                download.setDownloadFileName(path.name)
                download.accept()
            except Exception:
                download.cancel()

        profile.downloadRequested.connect(save)
        self.references.extend((container, save))


def desktop_engine():
    if sys.platform == 'win32':
        return 'edgechromium'
    if sys.platform.startswith('linux'):
        # Never enable Chromium's no-sandbox bypass. pywebview's Qt renderer
        # adds it automatically on these distributions, so decline that path.
        try:
            distribution = platform.freedesktop_os_release().get('ID', '')
        except OSError:
            distribution = ''
        if distribution in ('arch', 'manjaro', 'nixos', 'rhel', 'pop'):
            raise DesktopProblem('The native Qt renderer is not qualified on this distribution. Use --browser with your ordinary desktop browser.')
        unsafe = os.environ.get('QTWEBENGINE_DISABLE_SANDBOX', '').lower() not in ('', '0', 'false')
        flags = (os.environ.get('QTWEBENGINE_CHROMIUM_FLAGS', '') + ' ' + os.environ.get('CHROMIUM_FLAGS', '')).lower()
        if unsafe or '--no-sandbox' in flags or '--disable-setuid-sandbox' in flags:
            raise DesktopProblem('Remove Chromium sandbox-disable settings before starting the desktop application.')
        return 'qt'
    raise DesktopProblem('The native desktop shell currently supports Linux and Windows. Use --browser for the local interface on this platform.')


def open_desktop(runtime):
    engine = desktop_engine()
    try:
        webview = importlib.import_module('webview')
    except ImportError:
        raise DesktopProblem('The desktop engine is not installed. Run the desktop installer, or use assessment-atlas --browser for the local interface.') from None
    webview.settings.update({'ALLOW_FILE_URLS': False, 'ALLOW_DOWNLOADS': True,
                             'OPEN_EXTERNAL_LINKS_IN_BROWSER': False,
                             'IGNORE_SSL_ERRORS': False, 'REMOTE_DEBUGGING_PORT': None})
    policy = LocalWindowPolicy(runtime.url)
    # Start blank. If a native guard cannot be installed, the assessment UI and
    # its session are never loaded into an unguarded renderer.
    window = webview.create_window(f'Assessment Atlas {__version__}', url='about:blank',
                                   width=1440, height=950, min_size=(960, 640),
                                   text_select=True, background_color='#101a20')
    failure = []
    guarded = threading.Event()
    inspected = threading.Event()

    def install():
        try:
            native = window.native.webview
            if engine == 'qt':
                policy.install_qt(native, window.native)
            else:
                policy.install_edge(native)
            guarded.set()
        except Exception:
            failure.append('The native window could not install its local navigation boundary. Use --browser or repair the desktop engine.')
        finally:
            inspected.set()

    def show_app():
        if not inspected.wait(15) or not guarded.is_set():
            if not failure:
                failure.append('The native window did not finish its protected startup. Use --browser or repair the desktop engine.')
            window.destroy()
            return
        window.load_url(runtime.url)

    window.events.before_show += install
    try:
        webview.start(show_app, gui=engine, debug=False, private_mode=True, http_server=False)
    except Exception:
        raise DesktopProblem('The native desktop window could not start. Check the installed desktop dependencies, or use assessment-atlas --browser.') from None
    if failure:
        raise DesktopProblem(failure[0])


def report_windowed_failure(problem):
    """pythonw has no terminal: make a failed launcher visible to its operator."""
    if sys.platform != 'win32' or sys.stderr is not None:
        return False
    # DesktopProblem messages are fixed actionable application text. Filesystem
    # exceptions may contain user paths, so the native dialog keeps those out.
    explanation = str(problem)[:600] if isinstance(problem, DesktopProblem) else (
        'Atlas could not open its protected local data or start its runtime. '
        'Check the desktop installation and your access to the data folder. '
        'Saved assessments have not been deleted.')
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, explanation, 'Assessment Atlas could not start', 0x10)
        return True
    except (OSError, AttributeError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description='Assessment Atlas on this computer: local execution uses this host and its VPN routes.')
    parser.add_argument('--data-dir', type=Path, default=None, help='Protected local assessment storage; retained across application updates.')
    parser.add_argument('--browser', action='store_true', help='Open the same local application in your normal browser instead of the optional native window; keep this process running.')
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):
        parser.exit(1, 'Assessment Atlas requires Python 3.12 or newer.\n')
    try:
        with DesktopRuntime(args.data_dir) as runtime:
            print(f'Assessment Atlas {__version__}: {runtime.url}\nExecution and VPN routes: this computer. Saved work: {runtime.guard.directory}', flush=True)
            if args.browser:
                if not webbrowser.open(runtime.url):
                    print('Open the local URL above in your browser. Press Ctrl+C here when finished.', flush=True)
                runtime.thread.join()
            else:
                open_desktop(runtime)
    except KeyboardInterrupt:
        pass
    except (DesktopProblem, ImportProblem, OSError) as exc:
        if report_windowed_failure(exc) or sys.stderr is None:
            raise SystemExit(1) from None
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
