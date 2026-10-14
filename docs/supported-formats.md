# Supported import formats — 0.4.0

All six adapters are implemented and exercised with synthetic fixtures and direct browser uploads. Bounded actual Nmap 7.95, Linux iproute2 6.1.0 and corroborated manual intake are now verified in [Live validation](live-validation.md). Nessus/Nuclei/httpx remain synthetic-only; no exhaustive installed-tool/version matrix is claimed. Support is for the field shapes below, not every tool version or extension. Unknown/unmapped fields remain in the original file held by the operator; the UI gives a coverage warning. Import is atomic: malformed/unsupported structures fail without partially saving. No archive, PDF, Nessus .db, execution template, or executable content is accepted.

Files must be UTF-8 text (optional BOM), at most 8 MiB. XML/custom DTD entities are rejected; Nmap's inert default declaration and stylesheet instruction are stripped without loading them. JSON duplicate keys, non-finite values and excessive nesting/items are rejected. XML depth is capped at 32/100,000 elements; JSON at depth 32/150,000 values; imports at 5,000 entities/30,000 observations. Long normalized strings are capped at 12,000 characters. Reviewable metadata can supply missing collection time (ISO with offset), source version, testing position and network context. These do not overwrite known source timestamps.

## Nmap XML

Requires `nmaprun` with `host` results. Maps host state, address attributes, hostname values, port/protocol/state, service attributes including detection method/confidence, OS matches as inferred claims, script output attributes and ordered trace/hop attributes. Does not normalize arbitrary nested NSE tables or infer switch wiring/VLANs. Missing hops and unanswered ports remain limited source evidence. `up` with `reason="user-set"` remains a configured scanner assumption with unknown reachability, even if all ports are filtered; independently responding ports retain their separate observed state. Missing discovery status remains unknown. Adapter revision is 2, and prior saved derivations are retained. Source version comes from `nmaprun/@version`; epoch source times are converted to UTC.

Prefer XML output from an authorized Nmap run (`-oX`) to console/grepable output. Format reference: [Nmap XML documentation](https://nmap.org/book/output-formats-xml-output.html). Fixture: [nmap.xml](../fixtures/nmap.xml).

## Nessus .nessus XML v2

Requires `NessusClientData_v2/Report/ReportHost`. Maps selected host properties (`host-ip`, `host-fqdn`, `operating-system`, `mac-address`), each `ReportItem` as a scanner-reported finding with plugin ID/name and severity, description/plugin output/solution, endpoint attributes, and selected CVE/CVSS/plugin-version/reference fields as observations. Policy/credential sections are discarded. Non-ISO human timestamps remain unknown unless supplied as import metadata. Scanner version remains unknown unless supplied; plugin versions are separately retained.

No `.db`, PDF/CSV reports, NASL execution or Nessus credentials are supported. The user's spoken “Nexus” is provisionally interpreted as Nessus; Nexus Repository imports are not claimed. Primary format reference: [Tenable export file formats](https://developer.tenable.com/docs/export-file-formats). Fixture: [scan.nessus](../fixtures/scan.nessus).

## Nuclei results JSON / JSONL

Accepts one result object, an array of result objects, or one JSON object per nonblank line. Each requires `template-id` and a target in `matched-at`, `url` or `host`. Maps `info.name`, `severity`, `description`, target/resource paths, IP where present, template/matcher/type/extracted results, and ISO `timestamp`. Each record creates separate device/resource candidates; review identity suggestions to reconcile them. Findings remain scanner assertions. Raw requests/responses, curl commands, template source and arbitrary template metadata are not normalized or executed.

This is result output, not a Nuclei input-target list or template file. Primary references: [Nuclei output options](https://docs.projectdiscovery.io/opensource/nuclei/running), [upstream ResultEvent fields](https://github.com/projectdiscovery/nuclei/blob/dev/pkg/output/output.go). Fixture: [nuclei.jsonl](../fixtures/nuclei.jsonl).

## ProjectDiscovery httpx results JSON / JSONL

Same object/array/JSONL layouts; each record requires `url`. Maps resource association, optional `ip`/`host_ip` or IP-valued `host`, ISO `timestamp`, `status_code`, `title`, `webserver`, `tech`, `content_length`, `failed` and `error`. Hyphenated `status-code`/`content-length` aliases normalize to the underscore names when canonical fields are absent. No request is made to a URL, and a response/path is not a validated vulnerability or directory-traversal test. Source version requires metadata. Unsupported fields remain in the original.

References: [httpx JSON output](https://docs.projectdiscovery.io/opensource/httpx/running), [upstream result fields](https://github.com/projectdiscovery/httpx/blob/dev/runner/types.go). Fixture: [httpx.jsonl](../fixtures/httpx.jsonl).

## Linux iproute2 bundle (`linux-ip/1`)

Wrap the JSON arrays from `ip -j address show`, `ip -j route show table all`, and `ip -j neigh show` in this envelope:

```json
{"format":"linux-ip/1","device":"device name","version":"iproute2 version","collected_at":"2026-10-12T10:00:00Z","addresses":[],"routes":[],"neighbors":[]}
```

Address records require `ifname`; `addr_info` entries require `local` with a valid prefix length. Interface/index/MAC/operational attributes and address assignments are preserved. CIDR memberships are inferred from assignments. Route records require `dst` and retain operational route attributes. Neighbor records require `dst` and `dev` and preserve state/MAC as operational neighbor evidence. Neither a REACHABLE neighbor-state label nor a route proves a successful application probe, physical switch wiring or VLAN membership. Empty/missing arrays yield only a device candidate and explicit metadata gaps.

Use [the explicit capture helper](../tools/capture_linux.py) as described in [Getting started](../GETTING_STARTED.md). It is not an integrated collector and never runs during import. Reference: [ip JSON output option](https://www.man7.org/linux/man-pages/man8/ip.8.html), [iproute2 upstream address output](https://github.com/iproute2/iproute2/blob/main/ip/ipaddress.c). Fixture: [device.json](../fixtures/device.json).

## Common manual evidence (`atlas-evidence/1`)

The UI downloads an editable template. Supported fields:

```json
{
  "format":"atlas-evidence/1", "source_version":"manual 1",
  "entities":[
    {"key":"router","label":"Synthetic router","kind":"device","addresses":["192.0.2.1"]},
    {"key":"peer","label":"Synthetic peer","kind":"device","addresses":["192.0.2.20"]}
  ],
  "observations":[{
    "subject":"router","target":"peer","kind":"local neighbor",
    "status":"unknown","basis":"manual","value":{"reason":"Replace with actual evidence and limits"},
    "collected_at":null
  }],
  "findings":[]
}
```

Entity keys must be unique nonempty strings within a file. Kinds: device, interface, subnet, service, application, hop. Subjects/targets must reference declared keys. Observation kind is a descriptive typed relationship/fact label; use established meanings in [Architecture](architecture.md). Status: observed/inferred/unknown. Basis: configured/operational/active test/passive/manual. Optional findings require a known `subject`; title/severity/description/external ID are normalized as imported assertions, never independently validated claims. The source location refers to the JSON record index, so keep protected original references or explanation in the observation value when needed.

There is no automatic import of exported `atlas-results/1` as a workspace backup; use stopped-database backup for recovery. Fixture: [manual.json](../fixtures/manual.json).

## Atlas native web envelope (`atlas-web/1`)

Auto-detection accepts a source in web-enumeration, web-workbench, web-payload, web-proxy, web-browser or web-scanner; 1–100 events per batch. A single event requires a stable ID. Each event supplies URL, captured_at, bounded request/response headers/text/body digests, optional links/parameter names/test/interception/issue evidence. Exact sources remain assertions for offline imports; native collector artifacts record their separate intake mode. Tool version and parser revision/time/vantage persist.

Logical host/service/origin/resource/parameter entities and typed request/response/link/transport/test observations are normalized. Query values/sensitive headers are withheld; body excerpts are metadata-only by default or bounded best-effort redacted text when explicitly enabled. Known query, form and top-level JSON field names are retained without values. A reported link is unknown until separately fetched; failure stays unknown. Source issues are scanner-reported, never independently validated impact. Web resource kinds do not establish physical topology.

Web adapter revision 4 retains optional authentication context (mode, session_verified, purpose, generation) as source evidence, plus hidden-input scrubbing. It retains baseline/control/run IDs in test observations and original/edited response correlation in interception observations. Offline assertions of authentication are not independent proof. Revision 4 also maps bounded WebSocket direction/opcode/count/digest and optional redacted text (binary bodies withheld), callback interaction/correlation/issued-probe bindings and HTTP version/TLS/pinned-address evidence. HTTP/3 services have separate UDP/QUIC associations. A callback associated with a target resource leaves service association unknown and does not prove target causality. Offline callback/transport labels are source assertions. Historical adapter-2/3 derivations stay immutable and can be re-derived without rewriting the source. Other adapters remain revision 2.

Repeated identical events deduplicate; conflicting content under one ID is rejected. Imported envelopes do not run a proxy/browser/check or contact URLs. Native live request limits and per-tool semantics are in [Setup](web-tools.md); [Coverage](native-web-coverage.md) lists exact checks and unsupported families/protocols. Raw messages are transient, not retained originals; keep protected source evidence separately where available. [Synthetic web fixture](../fixtures/web.json) demonstrates inert manual import of the envelope.
