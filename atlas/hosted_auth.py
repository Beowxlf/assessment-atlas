"""Single-operator HTTPS deployment authentication; loopback remains the default."""
import argparse
from collections import deque
import getpass
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
import json
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit

from .importers import ImportProblem

ROUNDS = 600_000
SESSION_SECONDS = 8 * 3600


def public_origin(value):
    if not isinstance(value, str) or len(value) > 250:
        raise ImportProblem('Public URL must be one HTTPS origin.')
    u = urlsplit(value)
    try:
        port = u.port
    except ValueError as exc:
        raise ImportProblem('Invalid public URL port.') from exc
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise ImportProblem('Public URL must be one HTTPS origin without credentials or a path.')
    if any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-:' for c in u.hostname.lower()) or ':' in u.hostname:
        raise ImportProblem('Use a DNS name or IPv4 address for the public HTTPS origin.')
    return 'https://' + u.hostname.lower() + (':' + str(port) if port and port != 443 else '')


def password_record(password):
    if not isinstance(password, str) or not 15 <= len(password) <= 200:
        raise ImportProblem('Choose an operator password of 15–200 characters.')
    salt = secrets.token_bytes(32)
    return {'format': 'atlas-operator-auth/1', 'algorithm': 'pbkdf2-sha256', 'rounds': ROUNDS,
            'salt': salt.hex(), 'digest': hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ROUNDS).hex()}


def save_password(path, password):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = password_record(password)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as file:
        json.dump(record, file)


class HostedAuth:
    def __init__(self, origin, path, clock=time.time):
        self.origin = public_origin(origin)
        self.host = urlsplit(self.origin).netloc
        self.clock, self.lock = clock, threading.RLock()
        self.sessions, self.attempts = {}, deque()
        try:
            path = Path(path)
            if os.name != 'nt' and path.stat().st_mode & 0o077:
                raise ImportProblem('Operator password file must be readable only by its owner (chmod 600).')
            record = json.loads(path.read_text(encoding='utf-8'))
            if record.get('format') != 'atlas-operator-auth/1' or record.get('algorithm') != 'pbkdf2-sha256' or record.get('rounds') != ROUNDS:
                raise ValueError()
            self.salt, self.digest = bytes.fromhex(record['salt']), bytes.fromhex(record['digest'])
            if len(self.salt) != 32 or len(self.digest) != 32:
                raise ValueError()
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ImportProblem('Create a protected operator password with python -m atlas.hosted_auth before hosted startup.') from exc

    def trusted(self, headers, peer):
        # The listener remains loopback. The documented reverse proxy overwrites
        # Host and proto; arbitrary Forwarded/X-Forwarded-Host are never trusted.
        return peer in ('127.0.0.1', '::1') and headers.get('Host') == self.host and headers.get('X-Forwarded-Proto') == 'https'

    def session(self, header):
        try:
            cookies = SimpleCookie()
            cookies.load(header or '')
            token = cookies.get('atlas_session')
            key = hashlib.sha256(token.value.encode()).hexdigest() if token else ''
        except (CookieError, UnicodeError):
            return None
        with self.lock:
            self._prune()
            record = self.sessions.get(key)
            return dict(record) if record else None

    def _prune(self):
        now = self.clock()
        self.sessions = {k:v for k,v in self.sessions.items() if v['expires'] > now}
        while self.attempts and self.attempts[0] <= now - 60:
            self.attempts.popleft()

    def login(self, password):
        with self.lock:
            self._prune()
            if len(self.attempts) >= 5:
                raise ImportProblem('Login attempt limit reached. Wait one minute before retrying.')
            self.attempts.append(self.clock())
            if not isinstance(password, str) or not 15 <= len(password) <= 200:
                return None
            digest = hashlib.pbkdf2_hmac('sha256', password.encode(), self.salt, ROUNDS)
            if not hmac.compare_digest(digest, self.digest):
                return None
            if len(self.sessions) >= 32:
                oldest = min(self.sessions, key=lambda k:self.sessions[k]['expires'])
                del self.sessions[oldest]
            token = secrets.token_urlsafe(32)
            record = {'id':secrets.token_urlsafe(32), 'nonce':secrets.token_urlsafe(32), 'expires':self.clock() + SESSION_SECONDS}
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = record
            return token, dict(record)

    def logout(self, header):
        cookies = SimpleCookie()
        try:
            cookies.load(header or '')
            if cookies.get('atlas_session'):
                with self.lock:
                    self.sessions.pop(hashlib.sha256(cookies['atlas_session'].value.encode()).hexdigest(), None)
        except CookieError:
            pass

    @staticmethod
    def cookie(token='', expire=False):
        return f'atlas_session={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={0 if expire else SESSION_SECONDS}'


def main():
    parser = argparse.ArgumentParser(description='Create an Atlas hosted operator password without putting it in command arguments.')
    parser.add_argument('--data-dir', type=Path, required=True)
    args = parser.parse_args()
    password = getpass.getpass('New Atlas operator password (15–200 characters): ')
    if password != getpass.getpass('Repeat password: '):
        raise SystemExit('Passwords do not match.')
    try:
        save_password(args.data_dir / 'operator-auth.json', password)
    except FileExistsError:
        raise SystemExit('An operator password already exists. Preserve it; no overwrite was performed.')
    print('Protected password hash created. Run the hosted server behind the documented HTTPS proxy.')


if __name__ == '__main__':
    main()
