"""Bounded, non-executing import adapters. No network or subprocess access."""
import datetime as dt
import io
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 30000
VERSION = "1"
SUPPORTED = ("nmap", "nessus", "nuclei", "httpx", "linux-ip", "atlas")


class ImportProblem(ValueError):
    pass


def clean(value):
    text = str(value or "")[:12000]
    text = re.sub(r"(?im)(password|passwd|secret|token|authorization|api[-_]?key|community)(\s*[=:]\s*)[^\s<,;]+", r"\1\2[redacted]", text)
    text = re.sub(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", text)
    return text


def timestamp(value):
    if not value:
        return None
    try:
        if str(value).isdigit():
            return dt.datetime.fromtimestamp(int(value), dt.timezone.utc).isoformat()
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.isoformat() if parsed.tzinfo else None
    except (ValueError, OverflowError, OSError):
        return None


def parse_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ImportProblem("Duplicate JSON keys are ambiguous.")
            result[key] = value
        return result
    def constant(_):
        raise ImportProblem("Non-finite JSON numbers are unsupported.")
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise ImportProblem("Invalid JSON: " + str(exc)[:160]) from exc
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if depth > 32 or count > 150000:
            raise ImportProblem("JSON nesting or item limit exceeded.")
        if isinstance(item, dict):
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, depth + 1) for v in item)
    return value


def xml(text):
    # Nmap's inert default declaration and stylesheet PI are common exports.
    # Strip them; never load a DTD, stylesheet, entity, or URL.
    text = text.replace("<!DOCTYPE nmaprun>", "")
    text = re.sub(r"<\?xml-stylesheet\b.*?\?>", "", text, flags=re.I | re.S)
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ImportProblem("External/custom XML document types and entities are not accepted.")
    depth = count = 0
    try:
        parser = ET.iterparse(io.StringIO(text), events=("start", "end"))
        for event, _ in parser:
            if event == "start":
                depth += 1
                count += 1
                if depth > 32 or count > 100000:
                    raise ImportProblem("XML nesting or element limit exceeded.")
            else:
                depth -= 1
        return parser.root
    except ET.ParseError as exc:
        raise ImportProblem("Malformed XML: " + str(exc)[:160]) from exc


def items(value, label):
    if not isinstance(value, list):
        raise ImportProblem(label + " must be an array.")
    if len(value) > MAX_ITEMS:
        raise ImportProblem(label + " exceeds the record limit.")
    return value


class Bundle:
    def __init__(self, source, context):
        self.source = source
        self.context = context
        self.entities = []
        self.observations = []
        self.findings = []
        self.warnings = []
        self.source_version = "unknown"
        self._keys = set()

    def entity(self, key, label, kind="device", addresses=None):
        if key in self._keys:
            return key
        self._keys.add(key)
        self.entities.append({"key": str(key), "label": clean(label) or str(key), "kind": kind,
                              "addresses": [clean(a) for a in addresses or []]})
        if len(self.entities) > 5000:
            raise ImportProblem("Maximum 5,000 entities per import.")
        return key

    def obs(self, subject, kind, value, location, status="observed", basis="active test", target=None, time=None):
        if status not in ("observed", "inferred", "unknown"):
            raise ImportProblem("Claim status must be observed, inferred or unknown.")
        if basis not in ("configured", "operational", "active test", "passive", "manual"):
            raise ImportProblem("Unknown evidence basis.")
        value = json.loads(json.dumps(value, ensure_ascii=False), parse_constant=lambda _: None)
        def scrub(v):
            if isinstance(v, dict):
                return {str(k): "[redacted]" if re.search(r"password|secret|token|api.?key|authorization", str(k), re.I) else scrub(x) for k, x in v.items()}
            if isinstance(v, list):
                return [scrub(x) for x in v]
            return clean(v) if isinstance(v, str) else v
        self.observations.append({"subject": subject, "target": target, "kind": kind, "value": scrub(value),
                                  "location": clean(location), "status": status, "basis": basis,
                                  "collected_at": timestamp(time) or self.context.get("collected_at"),
                                  "vantage": clean(self.context.get("vantage")) or "unknown"})
        if len(self.observations) > MAX_ITEMS:
            raise ImportProblem("Observation limit exceeded.")

    def finding(self, subject, title, severity, description, location, external_id, time=None):
        if severity not in ("info", "low", "medium", "high", "critical", "unknown"):
            severity = "unknown"
        self.obs(subject, "scanner report", {"title": title, "severity": severity, "external_id": external_id}, location, time=time)
        self.findings.append({"subject": subject, "title": clean(title), "severity": severity,
                              "description": clean(description), "external_id": clean(external_id),
                              "validation": "scanner-reported", "status": "open", "location": location})


def nmap(text, context):
    root = xml(text)
    if root.tag != "nmaprun":
        raise ImportProblem("Expected Nmap nmaprun XML.")
    b = Bundle("nmap", context)
    b.source_version = root.get("version", "unknown")
    for index, host in enumerate(root.findall("host")):
        loc = f"/nmaprun/host[{index + 1}]"
        addresses = [a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6") and a.get("addr")]
        names = [x.get("name") for x in host.findall("hostnames/hostname") if x.get("name")]
        key = b.entity(f"host:{index}", (names or addresses or [f"Host {index+1}"])[0], addresses=addresses)
        when = host.get("endtime") or root.get("start")
        b.obs(key, "host state", dict(host.find("status").attrib) if host.find("status") is not None else {"state": "unknown"}, loc + "/status", time=when)
        for a in host.findall("address"):
            b.obs(key, "address", dict(a.attrib), loc + "/address", time=when)
        for name in names:
            b.obs(key, "name", name, loc + "/hostnames", time=when)
        for osmatch in host.findall("os/osmatch"):
            b.obs(key, "OS fingerprint", dict(osmatch.attrib), loc + "/os/osmatch", status="inferred", time=when)
        for i, port in enumerate(host.findall("ports/port")):
            service = port.find("service")
            state = port.find("state")
            attrs = {**port.attrib, "state": state.get("state", "unknown") if state is not None else "unknown",
                     "signature": dict(service.attrib) if service is not None else {}}
            svc = b.entity(f"{key}:port:{i}", f"{port.get('portid')}/{port.get('protocol')} {(service.get('name') if service is not None else '')}", "service")
            b.obs(key, "service association", attrs, loc + f"/ports/port[{i+1}]", target=svc, time=when)
            for script in port.findall("script"):
                b.obs(svc, "script output", dict(script.attrib), loc + f"/ports/port[{i+1}]/script", time=when)
        previous = None
        for i, hop in enumerate(host.findall("trace/hop")):
            hopkey = b.entity(f"{key}:hop:{i}", hop.get("ipaddr", "Unknown hop"), "hop", [hop.get("ipaddr")] if hop.get("ipaddr") else [])
            b.obs(key, "routed path hop", dict(hop.attrib), loc + f"/trace/hop[{i+1}]", target=hopkey, time=when)
            if previous:
                b.obs(previous, "routed path sequence", {"destination": addresses, "ttl": hop.get("ttl")}, loc + "/trace", target=hopkey, time=when)
            previous = hopkey
    b.warnings.append("Nmap labels, OS matches and script output are source claims; they do not prove physical wiring or validated impact.")
    return b


def nessus(text, context):
    root = xml(text)
    if root.tag != "NessusClientData_v2":
        raise ImportProblem("Only NessusClientData_v2 .nessus XML reports are supported.")
    b = Bundle("nessus", context)
    b.source_version = "NessusClientData_v2 (scanner version unknown)"
    hosts = root.findall("Report/ReportHost")
    if not hosts:
        raise ImportProblem("No ReportHost results found; policies and .db exports are unsupported.")
    for i, host in enumerate(hosts):
        loc = f"/NessusClientData_v2/Report/ReportHost[{i+1}]"
        props = {tag.get("name"): tag.text or "" for tag in host.findall("HostProperties/tag")}
        ip = props.get("host-ip", "")
        key = b.entity(f"host:{i}", props.get("host-fqdn") or host.get("name") or ip, addresses=[ip] if ip else [])
        for prop in ("host-ip", "host-fqdn", "operating-system", "mac-address"):
            if prop in props:
                b.obs(key, prop, props[prop], loc + f"/HostProperties/tag[@name='{prop}']", time=props.get("HOST_END"))
        for j, report in enumerate(host.findall("ReportItem")):
            location = loc + f"/ReportItem[{j+1}]"
            title = report.get("pluginName", "Unnamed scanner result")
            try:
                level = int(report.get("severity", "0"))
                severity = ("info", "low", "medium", "high", "critical")[level] if 0 <= level <= 4 else "unknown"
            except (ValueError, IndexError):
                severity = "unknown"
            details = "\n\n".join(clean(report.findtext(k)) for k in ("description", "plugin_output", "solution") if report.findtext(k))
            b.finding(key, title, severity, details, location, report.get("pluginID", "unknown"), props.get("HOST_END"))
            b.obs(key, "scanner references", {"cve": [c.text for c in report.findall("cve")],
                                              "cvss_base_score": report.findtext("cvss_base_score"),
                                              "cvss3_base_score": report.findtext("cvss3_base_score"),
                                              "plugin_version": report.findtext("plugin_version"),
                                              "see_also": report.findtext("see_also")}, location, time=props.get("HOST_END"))
            b.obs(key, "scanner endpoint", {"port": report.get("port"), "protocol": report.get("protocol"), "service": report.get("svc_name")}, location, time=props.get("HOST_END"))
    b.warnings.append("Nessus results are scanner-reported; policy/credential sections are discarded. Human-formatted HOST_END values are not treated as known timestamps.")
    return b


def events(text):
    stripped = text.lstrip()
    if stripped.startswith("["):
        return items(parse_json(text), "Results")
    if stripped.startswith("{"):
        try:
            one = parse_json(text)
            return [one]
        except ImportProblem:
            pass
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            try:
                result.append(parse_json(line))
            except ImportProblem as exc:
                raise ImportProblem(f"JSONL line {number}: {exc}") from exc
    return items(result, "JSONL results")


def web_results(text, context, source):
    b = Bundle(source, context)
    for i, event in enumerate(events(text)):
        if not isinstance(event, dict):
            raise ImportProblem(f"Result {i+1} must be an object.")
        loc = f"result[{i+1}]"
        address = event.get("ip") or event.get("host")
        target = event.get("matched-at") or event.get("url") or event.get("host")
        if source == "nuclei" and (not event.get("template-id") or not target):
            raise ImportProblem(f"Result {i+1} lacks Nuclei template-id or target.")
        if source == "httpx" and not event.get("url"):
            raise ImportProblem(f"Result {i+1} lacks httpx url.")
        parsed = urlsplit(str(target))
        label = parsed.hostname or str(address or target)
        ip = event.get("ip") or event.get("host_ip")
        if not ip and event.get("host"):
            try:
                ip = str(ipaddress.ip_address(event["host"]))
            except ValueError:
                pass
        if isinstance(ip, list):
            ips = [str(x) for x in ip]
        else:
            ips = [str(ip)] if ip else []
        key = b.entity(f"host:{i}", label, addresses=ips)
        resource = b.entity(f"resource:{i}", target, "application")
        b.obs(key, "application resource", {"url": target, "path": parsed.path}, loc, target=resource, time=event.get("timestamp"))
        if source == "nuclei":
            info = event.get("info", {})
            if not isinstance(info, dict):
                raise ImportProblem("Nuclei info must be an object.")
            b.finding(resource, info.get("name", event["template-id"]), info.get("severity", "unknown"), info.get("description", ""), loc, event["template-id"], event.get("timestamp"))
            b.obs(resource, "template match", {k: event[k] for k in ("template-id", "matcher-name", "type", "extracted-results") if k in event}, loc, time=event.get("timestamp"))
        else:
            response = {k: event[k] for k in ("status_code", "title", "webserver", "tech", "content_length", "failed", "error") if k in event}
            for old, new in (("status-code", "status_code"), ("content-length", "content_length")):
                if old in event and new not in response:
                    response[new] = event[old]
            b.obs(resource, "web response", response, loc, time=event.get("timestamp"))
    b.warnings.append("URLs are never fetched; version and testing position require supplied metadata. No template or curl command is executed.")
    return b


def linux_ip(text, context):
    data = parse_json(text)
    if not isinstance(data, dict) or data.get("format") != "linux-ip/1":
        raise ImportProblem("Expected linux-ip/1 envelope containing address, route and neighbor arrays.")
    b = Bundle("linux-ip", context)
    b.source_version = clean(data.get("version", "unknown"))
    when = data.get("collected_at")
    router = b.entity("device", data.get("device", "Linux device"))
    interfaces = {}
    for i, entry in enumerate(items(data.get("addresses", []), "addresses")):
        if not isinstance(entry, dict) or not entry.get("ifname"):
            raise ImportProblem("Address entry requires ifname.")
        iface = b.entity("interface:" + entry["ifname"], entry["ifname"], "interface")
        interfaces[entry["ifname"]] = iface
        b.obs(router, "interface", {k: entry[k] for k in ("ifindex", "ifname", "address", "operstate", "flags", "mtu") if k in entry}, f"addresses[{i}]", basis="operational", target=iface, time=when)
        for j, addr in enumerate(items(entry.get("addr_info", []), "addr_info")):
            if not isinstance(addr, dict) or not addr.get("local"):
                raise ImportProblem("addr_info requires local address.")
            b.obs(iface, "address assignment", addr, f"addresses[{i}].addr_info[{j}]", basis="operational", time=when)
            network = str(ipaddress.ip_network(f"{addr['local']}/{addr.get('prefixlen', 32 if ':' not in addr['local'] else 128)}", strict=False))
            subnet = b.entity("subnet:" + network, network, "subnet")
            b.obs(iface, "subnet membership", {"derived_from": f"addresses[{i}].addr_info[{j}]"}, f"addresses[{i}].addr_info[{j}]", status="inferred", basis="operational", target=subnet, time=when)
    for i, route in enumerate(items(data.get("routes", []), "routes")):
        if not isinstance(route, dict) or not route.get("dst"):
            raise ImportProblem("Route entry requires dst.")
        dst = b.entity("route:" + str(i), route["dst"], "subnet")
        b.obs(router, "operational route", route, f"routes[{i}]", basis="operational", target=dst, time=when)
    for i, neighbor in enumerate(items(data.get("neighbors", []), "neighbors")):
        if not isinstance(neighbor, dict) or not neighbor.get("dst") or not neighbor.get("dev"):
            raise ImportProblem("Neighbor entry requires dst and dev.")
        peer = b.entity("neighbor:" + str(i), neighbor["dst"], "device", [neighbor["dst"]])
        b.obs(interfaces.get(neighbor["dev"], router), "local neighbor", neighbor, f"neighbors[{i}]", basis="operational", target=peer, time=when)
    b.entities[0]["addresses"] = list(dict.fromkeys(a.get("local") for entry in data.get("addresses", []) for a in entry.get("addr_info", []) if a.get("local")))
    b.warnings.append("Kernel route and neighbor tables are operational observations, not proof of switch wiring, VLAN membership or successful reachability.")
    return b


def manual(text, context):
    data = parse_json(text)
    if not isinstance(data, dict) or data.get("format") != "atlas-evidence/1":
        raise ImportProblem("Expected atlas-evidence/1 common evidence envelope.")
    b = Bundle("atlas", context)
    b.source_version = clean(data.get("source_version", "unknown"))
    for entity in items(data.get("entities", []), "entities"):
        if not isinstance(entity, dict) or not isinstance(entity.get("key"), str) or not entity["key"]:
            raise ImportProblem("Each entity needs a nonempty string key.")
        if entity.get("kind", "device") not in ("device", "interface", "subnet", "service", "application", "hop"):
            raise ImportProblem("Unsupported entity kind.")
        if any(e["key"] == entity["key"] for e in b.entities):
            raise ImportProblem("Duplicate entity key.")
        b.entity(entity["key"], entity.get("label", entity["key"]), entity.get("kind", "device"), items(entity.get("addresses", []), "addresses"))
    keys = {e["key"] for e in b.entities}
    for i, obs in enumerate(items(data.get("observations", []), "observations")):
        if not isinstance(obs, dict) or obs.get("subject") not in keys or (obs.get("target") and obs["target"] not in keys):
            raise ImportProblem("Observation references an unknown entity.")
        if not isinstance(obs.get("kind"), str) or not obs["kind"]:
            raise ImportProblem("Observation requires kind.")
        b.obs(obs["subject"], obs["kind"], obs.get("value"), f"observations[{i}]", obs.get("status", "unknown"), obs.get("basis", "manual"), obs.get("target"), obs.get("collected_at"))
    for i, f in enumerate(items(data.get("findings", []), "findings")):
        if not isinstance(f, dict) or f.get("subject") not in keys:
            raise ImportProblem("Finding references an unknown entity.")
        b.finding(f["subject"], f.get("title", "Imported assertion"), f.get("severity", "unknown"), f.get("description", ""), f"findings[{i}]", f.get("external_id", "manual"))
        b.findings[-1]["validation"] = "imported assertion"
    b.warnings.append("Manual assertions retain their stated status; importing a claim does not independently validate it.")
    return b


def parse(content, source="auto", context=None):
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES:
        raise ImportProblem("Files must be UTF-8 text and no larger than 8 MiB.")
    context = context or {}
    content = content.removeprefix("\ufeff")
    context["collected_at"] = timestamp(context.get("collected_at"))
    if source == "auto":
        if "<nmaprun" in content[:2000]:
            source = "nmap"
        elif "<NessusClientData_v2" in content[:2000]:
            source = "nessus"
        else:
            first = events(content)
            obj = first[0] if first else {}
            if isinstance(obj, dict):
                source = {"linux-ip/1": "linux-ip", "atlas-evidence/1": "atlas"}.get(obj.get("format"), "nuclei" if "template-id" in obj else "httpx" if "url" in obj else "unknown")
    if source not in SUPPORTED:
        raise ImportProblem("Unsupported format. Choose a supported tool output or use the common evidence template.")
    try:
        bundle = {"nmap": nmap, "nessus": nessus, "linux-ip": linux_ip, "atlas": manual}.get(source, lambda t, c: web_results(t, c, source))(content, context)
    except (KeyError, TypeError, AttributeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ImportProblem):
            raise
        raise ImportProblem("Invalid or unsupported input structure: " + str(exc)[:160]) from exc
    if not bundle.entities:
        raise ImportProblem("No supported entities found in this input.")
    if not context.get("vantage"):
        bundle.warnings.append("Testing position is unknown; provide it when importing if you know it.")
    if not any(o["collected_at"] for o in bundle.observations):
        bundle.warnings.append("Collection time is unknown; import time is recorded separately.")
    bundle.warnings.append("Only fields described in the supported-format guide are normalized. Unmapped fields remain in the operator-held original file.")
    return bundle
