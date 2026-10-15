"""Installation identity, single-use execution reviews and fail-closed routes.

Reviews contain no credentials. Their authority is short-lived process memory;
saved host/interface expectations are plans, not a restored route or session.
"""
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import uuid

from .importers import ImportProblem


class ExecutionChanged(ImportProblem):
    """A reviewed host, route, source or authentication context was lost."""


def timestamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def interface_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value):
        raise ImportProblem('Choose one exact interface name of 1–15 characters, or system.')
    return value


def ip_json(arguments):
    executable = '/usr/sbin/ip' if Path('/usr/sbin/ip').exists() else '/usr/bin/ip'
    try:
        result = subprocess.run([executable, '-j', *arguments], capture_output=True, check=True, timeout=3, text=True)
        if len(result.stdout) > 65536:
            raise ValueError()
        rows = json.loads(result.stdout)
        if not isinstance(rows, list):
            raise ValueError()
        return rows
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ExecutionChanged('Execution interface or route could not be verified; no fallback is permitted.') from None


def linux_route(target, interface, runner=ip_json):
    """Verify a usable source and UP interface for one exact pinned IP."""
    try:
        target = str(ipaddress.ip_address(target))
        rows = runner(['route', 'get', target])
        if len(rows) != 1:
            raise ValueError()
        route = rows[0]
        if not isinstance(route,dict):raise ValueError()
        actual = interface_name(route.get('dev'))
        if interface != 'system' and actual != interface:
            raise ValueError()
        if route.get('type') in ('unreachable', 'prohibit', 'blackhole', 'throw'):
            raise ValueError()
        links = runner(['link', 'show', 'dev', actual])
        if len(links) != 1 or not isinstance(links[0],dict) or not isinstance(links[0].get('flags'),list) or 'UP' not in links[0]['flags']:
            raise ValueError()
        source = str(ipaddress.ip_address(route.get('prefsrc', route.get('src', ''))))
        if ipaddress.ip_address(source).version != ipaddress.ip_address(target).version:
            raise ValueError()
        measured={'target': target, 'interface': actual, 'source': source}
        if route.get('gateway'):
            measured['gateway']=str(ipaddress.ip_address(route['gateway']))
        ifindex=links[0].get('ifindex')
        if isinstance(ifindex,int) and not isinstance(ifindex,bool) and 1<=ifindex<=2147483647:
            measured['ifindex']=ifindex
        table=route.get('table')
        if isinstance(table,int) and not isinstance(table,bool) and 0<=table<=4294967295:
            measured['table']=table
        elif isinstance(table,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',table):
            measured['table']=table
        return measured
    except (ValueError, TypeError, ImportProblem, KeyError):
        raise ExecutionChanged('Reviewed execution route/interface/source is unavailable or changed. Reconnect on the execution host and review again.') from None


class ExecutionContexts:
    def __init__(self, store, clock=None, platform_name=None, route_runner=None):
        self.store = store
        self.clock = clock or time.monotonic
        self.platform = platform_name or sys.platform
        self.route_runner = route_runner or ip_json
        self.lock = threading.RLock()
        self.tokens = {}
        self.revoked_owners = {}
        self.session_validator = None
        self.atlas_port = None
        path = Path(store.path).with_name('execution-host.json')
        if path.is_symlink():
            raise ImportProblem('Execution host identity must be a protected regular file.')
        if not path.exists():
            payload = {'schema': 'atlas-execution-host/1', 'id': uuid.uuid4().hex}
            try:
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'w', encoding='utf-8') as file:
                    json.dump(payload, file)
            except FileExistsError:
                pass
        try:
            if path.stat().st_size > 4096:
                raise ValueError()
            saved = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(saved,dict) or saved.get('schema') != 'atlas-execution-host/1' or not re.fullmatch(r'[0-9a-f]{32}', saved.get('id', '')):
                raise ValueError()
            if os.name != 'nt':
                os.chmod(path, 0o600)
        except (OSError, ValueError, TypeError):
            raise ImportProblem('Execution host identity is invalid; preserve it and repair the installation identity before running tools.') from None
        self.host = {'id': saved['id'], 'name': platform.node()[:200] or 'Atlas host', 'platform': self.platform}

    def describe(self):
        interfaces = [{'name': 'system', 'up': True}]
        if self.platform.startswith('linux'):
            try:
                interfaces += [{'name': interface_name(row.get('ifname')), 'up': 'UP' in row.get('flags', [])} for row in self.route_runner(['link', 'show'])[:64]]
            except ImportProblem:
                pass
        return {'host': copy.deepcopy(self.host), 'interfaces': interfaces,
                'default_interface': 'tun0' if self.platform.startswith('linux') else 'system',
                'limits': 'Operations run on this Atlas installation. An explicit Linux interface is checked and socket-bound; system uses ordinary OS routing and does not attest a VPN. Reviews expire after 60 seconds and are single-use.'}

    def expectation(self, config):
        value = config.get('execution_context')
        if not isinstance(value, dict) or set(value) != {'host_id', 'interface'}:
            raise ImportProblem('Review an execution host and interface before starting this test.')
        if value['host_id'] != self.host['id']:
            raise ExecutionChanged('The saved execution host does not match this Atlas installation. Review the intended host before testing.')
        interface = interface_name(value['interface'])
        if not self.platform.startswith('linux') and interface != 'system':
            raise ExecutionChanged('This platform supports system routing only; a Linux host is required to attest a VPN interface.')
        return {'host_id': self.host['id'], 'interface': interface}

    def routes(self, scope, interface):
        addresses = sorted({value for pins in scope.pins.values() for value in pins})
        if not addresses or len(addresses) > 80:
            raise ImportProblem('Execution review needs a bounded resolved target scope.')
        if self.platform.startswith('linux'):
            return [linux_route(target, interface, self.route_runner) for target in addresses]
        return [{'target': target, 'interface': 'system', 'source': None} for target in addresses]

    def scope_digest(self, scope, expectation):
        return digest({'scope': scope.summary(), 'host': expectation})

    def binding(self, workspace, config, scope, expectation):
        # Session handles/inline credentials participate only in a transient
        # digest. They never appear in proof, persistent host ID or run plans.
        auth_identity = config.get('session_id') or digest(config.get('auth', {}))
        normalized={key:value for key,value in config.items() if key not in ('workspace','context_token','_execution_owner')}
        if config.get('session_id'):normalized.pop('auth',None)
        return digest({'workspace': workspace, 'owner': config.get('_execution_owner', 'local'),
                       'scope': self.scope_digest(scope, expectation), 'auth': auth_identity,
                       'reviewed_config':digest(normalized),
                       'role': config.get('access_role', ''), 'reference': config.get('access_reference', '')})

    def _session(self, workspace, config):
        if self.session_validator:
            try:
                self.session_validator(workspace, config)
            except ImportProblem:
                raise ExecutionChanged('Authentication context expired or changed. Re-establish the correct session and review execution again.') from None

    def preview(self, workspace, config):
        from .web_transport import Scope
        self.store.get(workspace)
        if config.get('_execution_owner','local') in self.revoked_owners:
            raise ExecutionChanged('Operator sign-in ended; establish a new sign-in before reviewing execution.')
        expectation = self.expectation(config)
        self._session(workspace, config)
        scope = Scope(config,self.atlas_port)
        proof = {'host': copy.deepcopy(self.host), 'interface': expectation['interface'],
                 'routes': self.routes(scope, expectation['interface']), 'scope_digest': self.scope_digest(scope, expectation),
                 'checked_at': timestamp(), 'policy': 'interface bound' if expectation['interface'] != 'system' else 'system routing; no VPN attestation'}
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.tokens = {key: row for key, row in self.tokens.items() if row['expires'] > self.clock()}
            if len(self.tokens) >= 64:
                raise ImportProblem('Too many pending execution reviews; wait for an old review to expire.')
            self.tokens[token] = {'expires': self.clock() + 60, 'owner': config.get('_execution_owner','local'), 'binding': self.binding(workspace, config, scope, expectation), 'proof': proof}
        return {**copy.deepcopy(proof), 'token': token, 'expires_in': 60}

    def forget_owner(self, owner):
        with self.lock:
            self.tokens={key:row for key,row in self.tokens.items() if row['owner']!=owner}
            self.revoked_owners={key:at for key,at in self.revoked_owners.items() if self.clock()-at<86400}
            self.revoked_owners[owner]=self.clock()

    def bind(self, workspace, scope, config, required=False):
        if config.get('execution_context') is None and not required:
            if config.get('session_id'):
                retained={key:copy.deepcopy(value) for key,value in config.items() if key not in ('auth','headers','body','context_token')}
                scope.execution_guard=SessionGuard(self,workspace,retained,{'host':self.host,'interface':'system'})
                scope.execution_guard.check()
            return None
        expectation = self.expectation(config)
        token = config.get('context_token')
        if not isinstance(token, str) or len(token) > 100:
            raise ImportProblem('Preview this execution context before starting. Reviews expire and cannot be reused.')
        with self.lock:
            row = self.tokens.pop(token, None)
        if not row or row['expires'] <= self.clock() or row['binding'] != self.binding(workspace, config, scope, expectation):
            raise ExecutionChanged('Execution review expired, was already used or no longer matches scope, host, operator or session. Review again.')
        self._session(workspace, config)
        retained={key:copy.deepcopy(config[key]) for key in ('authorized','url','path_prefix','extra_origins','exclude_paths','ca_pem','execution_context','session_id','investigation_id','access_role','access_reference','_execution_owner') if key in config}
        guard = ExecutionGuard(self, workspace, retained, row['proof'])
        guard.check()
        scope.execution_guard = guard
        return copy.deepcopy(guard.proof)


class ExecutionGuard:
    def __init__(self, manager, workspace, config, proof):
        self.manager, self.workspace, self.config = manager, workspace, config
        self.proof = copy.deepcopy(proof)

    def check(self):
        if self.config.get('_execution_owner','local') in self.manager.revoked_owners:
            raise ExecutionChanged('Operator sign-in ended; execution stopped with completed evidence retained.')
        if self.proof['host']['id'] != self.manager.host['id']:
            raise ExecutionChanged('Execution host changed; completed evidence is retained, and no fallback is permitted.')
        self.manager._session(self.workspace, self.config)
        class Pinned:
            pins = {'reviewed': [route['target'] for route in self.proof['routes']]}
        if self.manager.routes(Pinned(), self.proof['interface']) != self.proof['routes']:
            raise ExecutionChanged('Execution route or source changed; completed evidence is retained. Review the context before continuing.')

    def bind_socket(self, sock, address):
        self.check()
        if self.proof['interface'] == 'system':
            return
        route = next((route for route in self.proof['routes'] if route['target'] == address), None)
        if not route:
            raise ExecutionChanged('Connection address is outside the reviewed execution routes.')
        try:
            # A source bind alone does not prevent Linux from falling back to a
            # different interface. Require device binding too, or fail closed.
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_BINDTODEVICE', 25), self.proof['interface'].encode() + b'\0')
            sock.bind((route['source'], 0, 0, 0) if ':' in address else (route['source'], 0))
        except OSError:
            raise ExecutionChanged('The execution socket could not bind the reviewed interface/source. No unbound fallback was attempted.') from None


class SessionGuard(ExecutionGuard):
    """Legacy ordinary routing can still stop on session expiry or logout."""
    def check(self):
        if self.config.get('_execution_owner','local') in self.manager.revoked_owners:
            raise ExecutionChanged('Operator sign-in ended; completed evidence retained.')
        self.manager._session(self.workspace,self.config)
