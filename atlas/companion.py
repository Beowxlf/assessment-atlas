"""Optional HTTPS computation companion. No target execution or implicit upload."""
import hashlib
import http.cookiejar
import json
import re
import secrets
import ssl
import threading
import time
import webbrowser
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler

from . import __version__
from .hosted_auth import public_origin
from .importers import ImportProblem
from .vulnerability_match import identity, match_record, validate_inventory

REPOSITORY = 'https://github.com/Beowxlf/assessment-atlas'
RELEASE_API = 'https://api.github.com/repos/Beowxlf/assessment-atlas/releases/latest'
PROTOCOL = 'atlas-companion/1'
MAX_REPLY = 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ImportProblem('Companion and update requests must not redirect.')


def software_inventory(rows):
    """Exact allowlist: private asset fields cannot cross the companion boundary."""
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20:
        raise ImportProblem('Select 1–20 software identities for companion analysis.')
    for row in rows:
        if not isinstance(row, dict):
            raise ImportProblem('Software identities must be objects.')
        allowed = {'kind', 'cpe'} if row.get('kind') == 'cpe' else {'kind', 'ecosystem', 'name', 'version'}
        if set(row) != allowed:
            raise ImportProblem('Share only a CPE or package ecosystem/name/version, without asset fields.')
    selected = validate_inventory([{**r, 'subject': 'selected'} for r in rows],
                                  {'entities': [{'id': 'selected'}], 'observations': []})
    return [identity(row) for row in selected]


def inventory_digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def analyze(cache, data):
    """Bounded cache-only matching; neither targets nor public APIs are contacted."""
    if not isinstance(data, dict) or set(data) != {'protocol', 'inventory'} or data['protocol'] != PROTOCOL:
        raise ImportProblem('Unsupported companion analysis request.')
    rows = software_inventory(data['inventory'])
    records = cache.records(limit=5001)
    truncated = len(records) > 5000
    records = records[:5000]
    result, deadline = [], time.monotonic() + 15
    for index, row in enumerate(rows):
        matches, unknown, omitted = [], 0, 0
        for record in records:
            if time.monotonic() > deadline:
                raise ImportProblem('Companion analysis time limit reached; no clean verdict is available.')
            matched, reason = match_record(record, row)
            if matched is None:
                unknown += 1
            if matched:
                if len(matches) >= 30:
                    omitted += 1
                    continue
                snapshot = record.get('snapshot', {})
                matches.append({'id': record['id'], 'provider': record['provider'], 'reason': reason,
                                'severity': record['severity'], 'record_sha256': record['record_sha256'],
                                'source_sha256': snapshot.get('sha256'), 'source_date': snapshot.get('fetched_at') or snapshot.get('loaded_at'),
                                'publisher_verified': snapshot.get('publisher_verified', False)})
        result.append({'index': index, 'identity': row, 'matches': matches, 'unknown_candidates': unknown,
                       'matches_omitted': omitted})
    return {'protocol': PROTOCOL, 'inventory_sha256': inventory_digest(rows), 'results': result,
            'records_examined': len(records), 'cache_truncated': truncated,
            'limit': 'Cache-only advisory leads. An absent match is not a clean verdict. Product presence, patch/backport status, configuration and impact remain unverified.'}


def request_json(opener, url, data=None, headers=None):
    body = None if data is None else json.dumps(data).encode()
    req = Request(url, data=body, headers={'Accept': 'application/json', 'User-Agent': 'AssessmentAtlas/' + __version__,
                                         **({'Content-Type': 'application/json'} if body is not None else {}), **(headers or {})})
    try:
        with opener.open(req, timeout=25) as response:
            if response.headers.get_content_type() != 'application/json':
                raise ImportProblem('Expected a JSON response from the selected service.')
            raw = response.read(MAX_REPLY + 1)
            if len(raw) > MAX_REPLY:
                raise ImportProblem('Service response exceeds the 1 MiB limit.')
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError()
            return result
    except ImportProblem:
        raise
    except HTTPError as exc:
        raise ImportProblem('Service request failed (HTTP ' + str(exc.code) + '); check access and server version.') from None
    except (URLError, OSError, ValueError):
        raise ImportProblem('Service unavailable or TLS verification failed. Local assessments remain available.') from None


def secure_opener(ca_pem=''):
    context = ssl.create_default_context()
    if ca_pem:
        if not isinstance(ca_pem, str) or len(ca_pem.encode()) > 65536 or 'PRIVATE KEY' in ca_pem:
            raise ImportProblem('Supply only a public CA certificate, at most 64 KiB.')
        try:
            context.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError):
            raise ImportProblem('The public CA certificate is invalid.') from None
    # Do not send the companion password through ambient HTTP proxies.
    return build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect(), HTTPCookieProcessor(http.cookiejar.CookieJar()))


class Companion:
    def __init__(self):
        self.connections, self.reports, self.updates = {}, {}, {}
        self.lock = threading.RLock()

    def status(self, owner):
        with self.lock:
            c = self.connections.get(owner)
            return {'connected': bool(c), 'origin': c['origin'] if c else None,
                    'protocol': PROTOCOL, 'credentials': 'Connection and sign-in are process memory only; reconnect after restart.'}

    def update_check(self, owner):
        result = check_update()
        with self.lock:
            self.updates[owner] = result['url']
        return result

    def open_update(self, owner):
        with self.lock:
            url = self.updates.get(owner)
        if not url:
            raise ImportProblem('Check the release first.')
        if not webbrowser.open(url):
            raise ImportProblem('Open the verified release URL displayed in App & server using your browser.')
        return {'opened': True}

    def connect(self, owner, data):
        origin = public_origin(data.get('origin'))
        password = data.get('password')
        if not isinstance(password, str) or not 15 <= len(password) <= 200:
            raise ImportProblem('Enter the companion operator password.')
        opener = secure_opener(data.get('ca_pem', ''))
        request_json(opener, origin + '/api/login', {'password': password}, {'Origin': origin})
        session = {}
        try:
            session = request_json(opener, origin + '/api/session')
            capabilities = request_json(opener, origin + '/api/companion/capabilities')
            if capabilities.get('protocol') != PROTOCOL or capabilities.get('cache_analysis') is not True:
                raise ImportProblem('This server needs the companion-capable Atlas release.')
            if not isinstance(session.get('nonce'), str):
                raise ImportProblem('The companion session is invalid.')
        except Exception:
            if isinstance(session.get('nonce'), str):
                try:
                    request_json(opener, origin + '/api/logout', {}, {'Origin': origin, 'X-Atlas-Nonce': session['nonce']})
                except ImportProblem:
                    pass
            raise
        self.disconnect(owner)
        with self.lock:
            self.connections[owner] = {'origin': origin, 'opener': opener, 'nonce': session['nonce']}
        return self.status(owner)

    def disconnect(self, owner):
        with self.lock:
            previous = self.connections.pop(owner, None)
            self.reports = {key: value for key, value in self.reports.items() if value['owner'] != owner}
        if previous:
            try:
                request_json(previous['opener'], previous['origin'] + '/api/logout', {},
                             {'Origin': previous['origin'], 'X-Atlas-Nonce': previous['nonce']})
            except ImportProblem:
                pass
        return self.status(owner)

    def run(self, owner, workspace, subject, data):
        if data.get('allow_share') is not True:
            raise ImportProblem('Review and allow sharing the selected software identities first.')
        rows = software_inventory(data.get('inventory'))
        with self.lock:
            c = self.connections.get(owner)
        if not c:
            raise ImportProblem('Connect to your HTTPS computation companion first.')
        report = request_json(c['opener'], c['origin'] + '/api/companion/analyze',
                              {'protocol': PROTOCOL, 'inventory': rows}, {'Origin': c['origin'], 'X-Atlas-Nonce': c['nonce']})
        if report.get('protocol') != PROTOCOL or report.get('inventory_sha256') != inventory_digest(rows):
            raise ImportProblem('The companion result does not match the selected software identities.')
        # Keep untrusted results inert, bounded, and tied to this session/asset.
        text = json.dumps(report, ensure_ascii=False, indent=2)
        if len(text.encode()) > 11500:
            raise ImportProblem('Companion report is too large to retain as an evidence excerpt; select fewer identities.')
        with self.lock:
            if self.connections.get(owner) is not c:
                raise ImportProblem('Companion connection changed; review the analysis again.')
            self.reports = {k: v for k, v in self.reports.items() if time.monotonic() - v['at'] < 1800}
            if len(self.reports) >= 20:
                raise ImportProblem('Pending report limit reached; disconnect to clear reviewed reports.')
            key = secrets.token_urlsafe(24)
            self.reports[key] = {'owner': owner, 'workspace': workspace, 'subject': subject, 'text': text,
                                 'origin': c['origin'], 'at': time.monotonic()}
        return {'report_id': key, 'report': report, 'origin': c['origin']}

    def save(self, owner, workspace, key, store):
        with self.lock:
            r = self.reports.get(key)
            if not r or r['owner'] != owner or r['workspace'] != workspace or time.monotonic() - r['at'] > 1800:
                raise ImportProblem('Review a fresh companion report for this workspace first.')
            result = store.capture_selection(workspace, {'subject': r['subject'], 'source': 'advisory-analysis',
                'title': 'Companion advisory analysis — unvalidated leads', 'text': r['text']},
                {'processor': 'HTTPS computation companion', 'origin': r['origin'], 'protocol': PROTOCOL})
            self.reports.pop(key, None)
            return result


def check_update():
    release = request_json(secure_opener(), RELEASE_API)
    tag = release.get('tag_name', '')
    if not isinstance(tag, str) or not re.fullmatch(r'v?\d+\.\d+\.\d+', tag) or release.get('draft') or release.get('prerelease'):
        raise ImportProblem('The release service did not return a stable supported version.')
    page = REPOSITORY + '/releases/tag/' + tag
    if release.get('html_url') != page:
        raise ImportProblem('The release page is outside the configured Atlas repository.')
    version = lambda value: tuple(int(v) for v in value.removeprefix('v').split('.'))
    return {'installed': __version__, 'available': tag, 'newer': version(tag) > version(__version__), 'url': page,
            'policy': 'Manual update only. Review the release and checksums, stop Atlas and back up local data before installing. No downloaded code is executed by Atlas.'}
