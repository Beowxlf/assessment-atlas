# Native web capability and acceptance matrix — 0.3.0

Owner direction: native Burp-style capabilities **inside Assessment Atlas**. External Burp piping/extensions are no longer the requested direction and are not delivered. The six requested areas are minimum categories, not exhaustive parity. This release implements original bounded workflows in every category; **all-feature and scanner parity with Burp Suite is unfinished and unqualified**. No proprietary code, scanner rules or branding were copied. No Burp edition/license is required by Atlas. Repository licensing remains an owner decision.

Inventory checked October 12, 2026 against official [Burp tools](https://portswigger.net/burp/documentation/desktop/tools), [documentation contents](https://portswigger.net/burp/documentation/contents), [web application scans](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans) and [extension documentation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions). These identify the reference inventory; they do not establish Atlas equivalence. PortSwigger labels its native Scanner Professional. Atlas checks below are separate original implementations.

## Advanced implementation in 0.3.0

Implemented original native authenticated scan sessions (cookie/bearer/manual and explicit CSRF-aware login sequences), browser cookie handoff, repeated session checks and at most two login refreshes. Crawl-driven auditing, explicit form/JSON/API requests, neutral/repeat controls, direct assessment findings, five new audit families, four multi-position attack modes/processors, text response editing, eleven codec/hash operations, token sample distribution measurements, declarative response checks and inert OpenAPI inventory are now present. [Exact workflow/contracts](authenticated-scans.md). Verification remains bounded to owned synthetic positive/negative fixtures and the executed browser/package workflows; no all-feature or independent accuracy claim is made.

The following six-area table records the historical 0.2.0 baseline; changes in this release supersede its listed gaps only where described in the advanced contract above. Other gaps remain.

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

In 0.3.0 the scanner can audit discovered endpoints when crawl-and-audit is selected, or one explicit start request with crawling disabled. Active check families are opt-in; baseline, neutral/confirmation and session-check requests share the run budget. Explicit form/JSON API requests are supported without automatically submitting discovered forms. Missing/unsupported checks are not a clean security verdict. Bodies are bounded UTF-8 text; current scanner parsing does not expand compressed bodies or interpret binary formats.

## Broader inventory and concrete backlog

| Reference capability group | Atlas status | Work and acceptance needed |
| --- | --- | --- |
| Target/site map, scope, HTTP history/logger | Implemented bounded logical map, source/history filters and explicit scope | Qualify larger engagements and efficient temporal/resource views without identity conflation |
| Proxy/request message editor | Partial native workflow | Text response interception/editing is implemented up to 16 KiB; add binary/body encodings and streaming; fuzz framing/connection behavior against interoperability corpus |
| Repeater/Comparer | Partial request replay/diff and explicit GET/POST login sequences | HTTP/2, WebSocket frames and saved redacted request collections; richer general macros |
| Intruder/payload processing | Four multi-position modes, four processors plus unchanged mode, query/form/JSON points, session verification and bounded cancellation | Binary/arbitrary insertion points, efficient result grouping, distributed scheduling and independent workload trials |
| Browser/session handling | Isolated browser cookie handoff (including path-specific cookies), transient manual/bearer sessions, CSRF-aware explicit login sequences, protected checks and bounded refresh | Browser action recording, partitioned cookies/localStorage, service workers, automatic MFA/SSO replay and representative app corpus |
| Scanner: injection families | Partial: controlled SQL-error and template arithmetic differentials | Original bounded SQL/NoSQL/OS/LDAP/XPath/template/XML injection checks with causal controls, cleanup and known vulnerable/nonvulnerable fixture matrix |
| Scanner: browser/security families | Partial: original markup reflection, credentialed Origin reflection and explicit anonymous-content comparison | Context-sensitive XSS execution validation, CSRF, authorization/IDOR, session/authentication and clickjacking impact checks; measure false positives/negatives |
| Scanner: transport/server families | Not implemented | Request smuggling/desynchronization, traversal/file access, cache behavior, SSRF and redirect validation under exact bounded authority; isolate impact and verify cleanup |
| Out-of-band interactions/Collaborator | Not implemented | Owner-controlled interaction service, correlation/time window/privacy controls and explicit exposure authorization; no public service added |
| WebSockets | Not implemented; isolated browser blocks them | Frame capture/edit/replay, scope/size/lifecycle guards and real protocol fixtures |
| Sequencer/statistical token analysis | Partial: transient sample distributions/duplicate and per-position empirical entropy measurements | Secure transient sample handling and defensible statistical battery; distinguish distribution measurements from predictability |
| Decoder/encoding utilities | Implemented bounded UTF-8 codecs/hash UI; malformed inputs rejected | Native bounded text/binary codecs and round-trip/malformed corpus; never execute decoded content |
| Organizer/notes/reporting | Partial via evidence, activity/review/history and redacted exports | Saved request annotations/collections, richer issue narratives and assessment acceptance trial |
| Extension/custom-check APIs/Bambdas | Partial: original declarative literal response checks; no uploaded code executes | Versioned isolated plugin/check contract, permissions/resource controls, lifecycle and compatibility verification; no arbitrary uploaded code execution |
| Mobile, APIs, GraphQL/SOAP, browser matrices | Partial: explicit HTTP/JSON/form requests and inert OpenAPI 3.0/3.1 GET inventory | Schema-aware inventory, non-GET workflows and representative compatibility fixtures; no blanket protocol/vendor promise |
| Advanced edition ecosystem/AI/DAST automation | Not implemented | Define owner outcomes and original contracts before implementation; no license parity or commercial product claim |

No row labeled partial is complete parity. Authentication/session and bounded payload modes have advanced in 0.3.0. Remaining work includes WebSocket/protocol coverage, response binary/streaming support, broader scanner families and an independent controlled accuracy corpus. These remain concrete native product work rather than a plan to connect external Burp. [Setup/workflow](web-tools.md), [authenticated-scan contract](authenticated-scans.md), [architecture decision](adr/0004-transient-authenticated-audits.md), [security boundaries](web-security.md).
