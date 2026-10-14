"""Typed host operations shared by the web server and outbound Linux runner."""
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .importers import ImportProblem, clean

PROFILES = {
    'tcp-discovery': {'name':'Discover common TCP ports', 'tool':'nmap', 'description':'Connect scan of the 1,000 most common TCP ports; discovery status remains a configured assumption.'},
    'tcp-all': {'name':'Discover all TCP ports', 'tool':'nmap', 'description':'Bounded connect scan of all TCP ports; the time limit may leave coverage incomplete.'},
    'service-enumeration': {'name':'Enumerate selected services', 'tool':'nmap', 'description':'Light service version probes on an explicit port list; banners do not prove patch status.'},
    'http-headers': {'name':'Inspect HTTP response headers', 'tool':'curl', 'description':'One HEAD request to an explicit URL pinned to the scoped IP; redirects are retained without following.'},
}
TERMINAL_STATES = {'completed','failed','cancelled','timeout','blocked','interrupted'}


def target_ip(value):
    if not isinstance(value, str):
        raise ImportProblem('Use one exact IPv4 target address.')
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ImportProblem('Use one exact IPv4 target; ranges, names and shell commands are unsupported.') from exc
    if address.is_unspecified or address.is_multicast or str(address)=='255.255.255.255' or address.is_link_local:
        raise ImportProblem('Unspecified, multicast, broadcast and link-local targets are unsupported.')
    return str(address)


def scope_config(data):
    if not isinstance(data, dict):
        raise ImportProblem('Host connection scope must be an object.')
    targets, profiles = data.get('targets'), data.get('profiles')
    if not isinstance(targets,list) or not 1 <= len(targets) <= 16:
        raise ImportProblem('Allow 1–16 exact target IPv4 addresses for this connection.')
    targets = sorted({target_ip(value) for value in targets})
    if not isinstance(profiles,list) or not profiles or any(value not in PROFILES for value in profiles):
        raise ImportProblem('Choose the allowed host operation profiles.')
    interface = data.get('interface','tun0')
    if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',interface):
        raise ImportProblem('Expected VPN interface must be a Linux interface name of 1–15 characters.')
    return {'targets':targets,'profiles':sorted(set(profiles)),'interface':interface}


def ports(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9,-]{1,300}',value):
        raise ImportProblem('Ports must be a comma-separated list of numbers/ranges.')
    result=set()
    for part in value.split(','):
        fields=part.split('-')
        if len(fields) not in (1,2):
            raise ImportProblem('Invalid port list.')
        low, high=int(fields[0]),int(fields[-1])
        if not 1 <= low <= high <= 65535 or high-low >= 1000:
            raise ImportProblem('Use port numbers 1–65535 and at most 1,000 selected ports.')
        result.update(range(low,high+1))
        if len(result)>1000:
            raise ImportProblem('At most 1,000 selected ports.')
    return ','.join(str(value) for value in sorted(result))


def operation(data, scope):
    if not isinstance(data,dict):
        raise ImportProblem('Host operation must be an object.')
    if set(data) - {'profile','target','ports','url','timeout'}:
        raise ImportProblem('Unsupported operation fields. Commands, executable paths, scripts and environment overrides are refused.')
    scope=scope_config(scope)
    target=target_ip(data.get('target'))
    profile=data.get('profile')
    if target not in scope['targets'] or profile not in scope['profiles']:
        raise ImportProblem('This target/profile is outside the host connection scope.')
    timeout=data.get('timeout',180)
    if isinstance(timeout,bool) or not isinstance(timeout,int) or not 15 <= timeout <= 600:
        raise ImportProblem('Operation time limit must be 15–600 seconds.')
    plan={'profile':profile,'target':target,'timeout':timeout,'interface':scope['interface']}
    if profile=='service-enumeration':
        plan['ports']=ports(data.get('ports',''))
    elif data.get('ports'):
        raise ImportProblem('A port list applies only to service enumeration.')
    if profile=='http-headers':
        value=data.get('url')
        if not isinstance(value,str) or not 1 <= len(value) <= 2000 or any(ord(c)<33 or ord(c)>126 for c in value):
            raise ImportProblem('Use one ASCII HTTP(S) URL without whitespace or control characters.')
        u=urlsplit(value)
        try: port=u.port
        except ValueError as exc: raise ImportProblem('Invalid URL port.') from exc
        if u.scheme not in ('http','https') or not u.hostname or u.username or u.password or u.fragment or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',u.hostname):
            raise ImportProblem('Use an HTTP(S) URL without credentials or a fragment.')
        if port is not None and not 1 <= port <= 65535:
            raise ImportProblem('Invalid URL port.')
        if u.query:
            raise ImportProblem('Header inspection accepts paths without query parameters or credentials.')
        # A hostname is a deliberate vhost, pinned by curl --resolve. No DNS lookup.
        if re.fullmatch(r'[0-9.]+',u.hostname) and target_ip(u.hostname)!=target:
            raise ImportProblem('URL address must match the exact scoped target.')
        plan['url']=value
    elif data.get('url'):
        raise ImportProblem('A URL applies only to header inspection.')
    return plan


def command(plan, output):
    """Return argv only. Revalidate the plan with the local scope before calling."""
    common=['nmap','-sT','-Pn','-n','-T3','--max-retries','2','--max-rate','200','--host-timeout',str(plan['timeout'])+'s']
    if plan['profile'] in ('tcp-discovery','tcp-all','service-enumeration'):
        options={'tcp-discovery':['--top-ports','1000'], 'tcp-all':['-p-'], 'service-enumeration':['-sV','--version-light','-p',plan.get('ports','')]}[plan['profile']]
        return common + options + ['-oX',str(output),plan['target']]
    u=urlsplit(plan['url']);port=u.port or (443 if u.scheme=='https' else 80)
    return ['curl','--disable','--silent','--show-error','--head','--noproxy','*','--proto','=http,https','--connect-timeout','10','--max-time',str(plan['timeout']), '--max-filesize','65536','--resolve',f'{u.hostname}:{port}:{plan["target"]}','--output',str(output),'--url',plan['url']]


def plan_digest(plan):
    return hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def terminal_text(text):
    if not isinstance(text,str):
        raise ImportProblem('Terminal output must be text.')
    # Escape/control sequences from a scanned service must never reach the
    # operator terminal or create active HTML. Keep only newline/tab controls.
    text=re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]','',text)
    text=''.join(c for c in text if c in '\n\t' or ord(c)>=32 and ord(c)!=127)
    text=re.sub(r'(?im)^((?:set-cookie|cookie|authorization|proxy-authorization)\s*:)[^\n]*',r'\1 [redacted]',text)
    return clean(text)
