# Native web capability and acceptance matrix — 0.2.0

Owner direction: native Burp-style capabilities **inside Assessment Atlas**. External Burp piping/extensions are no longer the requested direction and are not delivered. The six requested areas are minimum categories, not exhaustive parity. This release implements original bounded workflows in every category; **all-feature and scanner parity with Burp Suite is unfinished and unqualified**. No proprietary code, scanner rules or branding were copied. No Burp edition/license is required by Atlas. Repository licensing remains an owner decision.

Inventory checked October 12, 2026 against official [Burp tools](https://portswigger.net/burp/documentation/desktop/tools), [documentation contents](https://portswigger.net/burp/documentation/contents), [web application scans](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans) and [extension documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions). These identify the reference inventory; they do not establish Atlas equivalence. PortSwigger labels its native Scanner Professional. Atlas checks below are separate original implementations.

## Six requested areas

| Area | Implemented native workflow | Executed acceptance | Remaining qualification |
| --- | --- | --- | --- |
| Crawl sites, discover paths, endpoints and parameters | Scoped GET crawl of links/resources; up to 50 explicit paths; query/form/JSON parameter names; HTTP status/body digests and logical origin/resource relationships | Owned local HTTP fixture, out-of-scope redirect/excluded-path guard, limits, partial results and cancellation; browser UI and map | Coverage is bounded; no automatic form submission, full sitemap/robots semantics, international URL matrix or universal crawler completeness |
| Edit/resend requests and inspect/compare responses | Seven HTTP methods, header/body editor, bounded response inspection, two transient response comparisons; normalized evidence saved | Real requests from UI, changed responses/diff, cross-workspace comparison guard, secret redaction | HTTP/1.1; no raw HTTP/2 framing, request sequences/macros, binary multipart uploads or WebSocket replay; credentials must be entered again or handled in the active browser |
| Bounded selected-parameter payload tests | One query/form parameter, up to 20 supplied payloads, one baseline, sequential rate/request/time limits; reflection/status-difference indicators | UI baseline plus two variants, reported findings and retained provenance; cancellation exercised by common runner | No multi-position attack modes, combinatorial scheduling, custom payload processors, credential guessing, automated exploitation or broad attack families |
| Intercept browser HTTPS and modify requests live | Authenticated loopback proxy; memory-only per-session CA; per-host TLS leaf; forward/edit/drop; 30-second fail-closed pending queue; independently verified upstream TLS | Actual HTTP edit/forward and TLS CONNECT with a trusting fixture client; negative upstream CA test; real isolated Edge HTTPS session | No response editing, WebSocket interception, transparent mode, HTTP/2/3, chunked uploads, binary request bodies or existing-browser/global trust automation |
| Authenticated JavaScript applications | Atlas-owned fresh Edge context through proxy; interactive sign-in, cookie session, JavaScript/XHR capture, explicit additional owned origins; context discarded on close | Actual isolated Edge HTTPS JavaScript login POST → cookie → authenticated API 200; credential redaction and JSON field names verified | Fixture demonstrates one session pattern, not reliable coverage of every app. No saved credentials, login recorder, MFA automation, session macros, mobile/browser matrix or service-worker/WebSocket support |
| Scanner coverage/accuracy | Eight original response indicator families plus two selected-parameter differential indicators listed below; findings stay scanner-reported | Positive fixture behavior, explicit single-request scanner flow, supported UI/reporting; no confirmed exploitation claim | Full Burp scanner coverage/accuracy remains unimplemented/unverified; independent false-positive/false-negative benchmark needed |

## Exact native check inventory

| Check ID | Trigger | Evidence and limit |
| --- | --- | --- |
| `atlas-csp` | HTML response omits CSP | Header absence only; no browser exploit demonstrated |
| `atlas-hsts` | HTTPS response omits HSTS | This response only; previously cached browser policy/deployment context unknown |
| `atlas-frame-policy` | HTML response lacks X-Frame-Options and CSP frame-ancestors | No sensitive clickjacking action tested |
| `atlas-nosniff` | Response lacks nosniff | Header indicator; MIME/browser context requires review |
| `atlas-cookie-httponly` | A Set-Cookie header lacks HttpOnly | Cookie value is not retained; cookie purpose/impact unknown |
| `atlas-cookie-secure` | HTTPS Set-Cookie lacks Secure | Cookie value is not retained; transport context requires review |
| `atlas-cors` | Wildcard allow-origin with credentials declaration | Informational combination; modern browsers reject wildcard credentialed reads; no disclosure established |
| `atlas-error-signature` | Captured text matches Python traceback, MySQL SQL syntax, unclosed quotation or Oracle error signature | Signature presence only; no root cause or causal injection established |
| `atlas-payload-reflection` | Supplied selected-parameter value occurs in bounded response text | Reflection only; browser execution and exploitation unproven |
| `atlas-status-difference` | Payload response status differs from its baseline | Difference only; baseline event/digest retained; cause unqualified |

The response-check button performs one scoped GET and passive analysis of that response. Payload tests are separate explicit requests. There is no automatic vulnerability audit of every crawled endpoint. Missing/unsupported checks are not a clean security verdict. Bodies are bounded UTF-8 text; current scanner parsing does not expand compressed bodies or interpret binary formats.

## Broader inventory and concrete backlog

| Reference capability group | Atlas status | Work and acceptance needed |
| --- | --- | --- |
| Target/site map, scope, HTTP history/logger | Implemented bounded logical map, source/history filters and explicit scope | Qualify larger engagements and efficient temporal/resource views without identity conflation |
| Proxy/request message editor | Partial native workflow | Add response interception/editing, binary/body encodings and streaming; fuzz framing/connection behavior against interoperability corpus |
| Repeater/Comparer | Partial request replay and response comparison | Add request sequences, HTTP/2, WebSocket frames and saved redacted templates; verify authentication isolation/replay semantics |
| Intruder/payload processing | Partial one-position sequential tests | Multi-position modes, scheduling/processors, result grouping, per-run authorization and cancellation tests |
| Browser/session handling | Partial isolated interactive session | Recorded login flows/session checks, CSRF refresh, MFA handoff, SPA/service-worker coverage and explicit additional-origin rules; benchmark actual authorized application corpus |
| Scanner: injection families | Not implemented | Original bounded SQL/NoSQL/OS/LDAP/XPath/template/XML injection checks with causal controls, cleanup and known vulnerable/nonvulnerable fixture matrix |
| Scanner: browser/security families | Not implemented beyond listed headers/reflection | Context-sensitive XSS execution validation, CSRF, authorization/IDOR, session/authentication and clickjacking impact checks; measure false positives/negatives |
| Scanner: transport/server families | Not implemented | Request smuggling/desynchronization, traversal/file access, cache behavior, SSRF and redirect validation under exact bounded authority; isolate impact and verify cleanup |
| Out-of-band interactions/Collaborator | Not implemented | Owner-controlled interaction service, correlation/time window/privacy controls and explicit exposure authorization; no public service added |
| WebSockets | Not implemented; isolated browser blocks them | Frame capture/edit/replay, scope/size/lifecycle guards and real protocol fixtures |
| Sequencer/statistical token analysis | Not implemented | Secure transient sample handling and defensible statistical battery; distinguish distribution measurements from predictability |
| Decoder/encoding utilities | Not implemented as a dedicated UI | Native bounded text/binary codecs and round-trip/malformed corpus; never execute decoded content |
| Organizer/notes/reporting | Partial via evidence, activity/review/history and redacted exports | Saved request annotations/collections, richer issue narratives and assessment acceptance trial |
| Extension/custom-check APIs/Bambdas | Not implemented | Versioned isolated plugin/check contract, permissions/resource controls, lifecycle and compatibility verification; no arbitrary uploaded code execution |
| Mobile, APIs, GraphQL/SOAP, browser matrices | Partial generic HTTP only | Schema-aware inventory, non-GET workflows and representative compatibility fixtures; no blanket protocol/vendor promise |
| Advanced edition ecosystem/AI/DAST automation | Not implemented | Define owner outcomes and original contracts before implementation; no license parity or commercial product claim |

No row labeled partial is complete parity. Prioritize protocol/interception hardening and a controlled scanner benchmark, then authentication/session coverage and payload modes. These remain concrete native product work rather than a plan to connect external Burp. [Setup/workflow](web-tools.md), [architecture decision](adr/0003-native-web-workbench.md), [security boundaries](web-security.md).
