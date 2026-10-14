# Native web capability and acceptance matrix — 0.4.0

Owner direction: original native Burp-style capabilities inside Assessment Atlas, with findings feeding the assessment directly. External Burp piping is not the requested implementation. The six original areas remain the minimum categories. HTTP/2/3, WebSockets, owner-controlled HTTP/DNS callbacks and twelve added audit selections are now implemented. **Complete Burp feature/scanner parity and independent scanner accuracy remain unqualified.** No proprietary scanner code/rules are copied; no Burp license is required. Project licensing remains an owner decision.

Inventory references checked October 12–14, 2026: [official tools](https://portswigger.net/burp/documentation/desktop/tools), [documentation](https://portswigger.net/burp/documentation/contents), [scans](https://portswigger.net/burp/documentation/desktop/running-scans/webapp-scans) and [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator). These establish the reference categories, not Atlas equivalence. Atlas's checks are original bounded implementations.

## Implemented workflows and evidence

| Area | Native implementation | Executed qualification | Remaining boundary |
| --- | --- | --- | --- |
| Crawl, paths, endpoints and parameters | Exact scoped GET crawling, explicit paths, query/form/top-level JSON field discovery, optional authenticated crawl/audit and API inventory | Owned HTTP/TLS fixtures, exclusions/redirects/pins, cancellation/partial budgets and direct map/evidence | No automatic form submission, complete robots/sitemap semantics or universal SPA/crawler coverage |
| Request editing/replay/comparison | Seven HTTP methods, text header/body editor, response comparison, selected upstream HTTP/1.1/2/3 | Actual UI HTTP/2 TLS and HTTP/3 QUIC, method/header/body fixture tests, CA rejection and recorded transport evidence | Single-request engines, bounded text bodies; no raw protocol frames or streaming/binary multipart editor |
| Payloads and processing | One-position, same-value, aligned and all-combination modes; query/form/JSON points, four processors, authenticated guards and baseline comparisons | Real UI combinations and positive/fixed payload/check fixtures | Up to five positions/200 combinations; no arbitrary byte insertion or distributed scheduling |
| Browser interception | Authenticated loopback HTTP/HTTPS proxy; request/text-response forward/edit/drop; original upstream and edited downstream retained separately; WS text/binary both-direction editing | Real UI HTTP edits and HTTPS JS/cookie flows; actual WS both-direction proxy edits and scoped Edge WSS text/binary capture | Browser hop is HTTP/1.1; no transparent/global proxy, full binary/streaming HTTP editor or independent framing fuzz audit |
| Authentication and JavaScript apps | Fresh Edge context, explicit cookie handoff, transient cookie/bearer/login sequences, hidden/JSON/header token extraction, protected guard and bounded refresh; authenticated WS handshake | Actual TLS browser login/handoff/scan; failure/loss/refresh, origin/path/expiry/workspace limits, secret-free evidence and budget tests | No browser action recorder, partitioned-cookie/localStorage handoff, service workers or automatic MFA/SSO replay |
| Scanner and findings | Existing header/cookie/error indicators, controlled injection/reflection/CORS/anonymous comparison, twelve added canary/callback selections; all findings enter assessment automatically | Synthetic vulnerable/fixed control matrix, real callback receipt, UI baseline/control inspection, review and report/export | Bounded syntax/canaries, source-reported assertions; no independent accuracy corpus or universal security verdict |
| WebSockets | Scoped classic WS/WSS complete-message capture, text/binary send, edit/replay, operator finding annotation and proxy interception | Real WS/WSS echo peers, authenticated guard/budget/scrubbing, both-direction edits; actual isolated Edge text/binary messages and outside-scope block | 64 KiB/message, four live manual channels; no permessage-deflate, HTTP/2 extended CONNECT or WebTransport/datagrams |
| Out-of-band testing | Owner-controlled bounded HTTP/DNS receiver, random transient tokens, short time window, probe/baseline correlation and direct source-reported findings | Actual HTTP and UDP DNS receipts, XML/URL callback canaries, wrong/expired token and API/workspace controls; live UI Findings/export | Remote routing/firewall/DNS/reverse proxy is operator-configured; receipt alone does not prove application causality/exploit impact |

Each event retains source/version/time/vantage, evidence status/basis, digest and capture/control links. Metadata is default; optional excerpts are best-effort scrubbed and bounded. Imported evidence is inert. Web adapter revision 4 preserves old derivations; legacy adapters stay revision 2. Schema stays 2; existing 0.2/0.3 workspaces need no migration. Current exact setup and limits are in [native setup](web-tools.md), [authenticated scans](authenticated-scans.md) and [protocol/callback/canary workflow](protocols-and-callbacks.md).

## Original check inventory

| Check ID / selection | Positive evidence | Limit |
| --- | --- | --- |
| `atlas-csp`, `atlas-hsts`, `atlas-frame-policy`, `atlas-nosniff` | Missing captured response policy/header | Response indicators, no browser impact proof |
| `atlas-cookie-httponly`, `atlas-cookie-secure` | Selected missing Set-Cookie flags | Values withheld; purpose/impact unknown |
| `atlas-cors`, `atlas-error-signature` | Wildcard/credentials declaration or recognized error text | Browser/backend context unqualified |
| `atlas-payload-reflection`, `atlas-status-difference`, `atlas-matrix-*` | Supplied payload reflected or status differs from baseline | No script execution or causal exploit verdict |
| `atlas-sql-error-differential` | Quote probe introduces repeatable error absent from baseline/neutral control | No query/data control proof |
| `atlas-template-expression` | Two arithmetic expected products with unique marker and neutral control | One template syntax, engine/impact unknown |
| `atlas-html-reflection` | Inert custom element appears verbatim in HTML | No script/DOM-context execution validation |
| `atlas-cors-origin` | Reserved arbitrary Origin reflected with credential declaration | SameSite/browser readability/sensitivity unknown |
| `atlas-authorization-comparison` | Explicit protected marker in both authenticated and credential-free GET | Anonymous comparison only; no role/object guessing |
| `atlas-sql-boolean` | Two true-shaped baseline matches and two stable false-shaped differences | One syntax, stable-text digest comparison only |
| `atlas-nosql-error`, `atlas-ldap-error`, `atlas-xpath-error` | New repeatable signature absent from baseline/neutral | Scalar/string canaries, no comprehensive backend exploitation |
| `atlas-command-arithmetic` | Two shell-shaped unique-marker arithmetic products plus neutral control | No arbitrary execution, files or privilege assertion |
| `atlas-file-canary` | Explicit owned file marker on probe/repeat, absent from baseline/missing-file control | No automated sensitive-file retrieval |
| `atlas-open-redirect` | Reserved external URL echoed exactly in redirect Location | Never followed; token/phishing impact unknown |
| `atlas-xml-entity` | Two bounded internal-entity values expand without full literal XML reflection | No external/file disclosure or expansion bomb |
| `atlas-csrf-canary` | Explicit isolated POST succeeds after selected token removal and foreign Origin | State/reset controlled by operator; browser feasibility unknown |
| `atlas-cache-canary` | Unique query-keyed canary repeats supplied host marker without probe header | Cleanup request bounded by run budget; no guaranteed invalidation/shared-key safety |
| `atlas-oob-http`, `atlas-oob-dns` (HTTP URL / external XML / manual token use) | Receiver observes matching issued HTTP/DNS token | Target causality/SSRF/RCE/data-access unverified |
| `atlas-websocket-operator` | Operator assertion linked to a captured WS message | Supplied interpretation, independently validated impact remains separate |
| `atlas-custom-*` | Operator-defined literal status/body/header predicates | At most ten original declarative rules; no uploaded code execution |

A completed run means its selected bounded queue finished. Unsupported/truncated/error responses, unselected families and partial runs are not clean findings. Every positive remains scanner-reported in assessment review and reports. Add independent validation with its own evidence rather than changing source truth.

## Remaining native work and qualification

| Group | Current boundary / work remaining |
| --- | --- |
| Protocol/editor completeness | Binary/streaming/chunked HTTP uploads, content decoding, raw frame collections/editor, HTTP/2 extended CONNECT, WS extensions and representative interoperability/fuzz matrix |
| Scanner depth and accuracy | Context-sensitive browser XSS execution, time-based/engine-specific injection, cross-role/IDOR, clickjacking/session impact, general SSRF/cache variants, request smuggling/desynchronization and independent false-positive/false-negative corpus |
| Browser/session automation | Action recording, partitioned-cookie/localStorage contract, service workers, representative app/SSO/MFA/browser/mobile fixtures |
| Sequencer and decoder | Existing bounded text codecs/hashes and token sample distributions; broader binary codecs and defensible statistical battery still needed; distribution is not predictability |
| Organizer and extensions | Existing evidence/activity/review/history/export and literal checks; richer saved request collections and versioned isolated plugin/check permissions/lifecycle remain open |
| API/ecosystem | Explicit JSON/form/XML requests and inert OpenAPI GET inventory; GraphQL/SOAP schema workflows, broad mobile/API matrices, commercial AI/DAST ecosystem and remote collaboration remain unimplemented |
| Operational acceptance | Larger engagements/concurrency, independent security audit, scanner benchmark, accessibility/browser/platform certification and owner assessment trial remain unqualified |

No row is a complete commercial-product parity claim. [ADR 0005](adr/0005-protocols-and-owned-interactions.md), [security boundaries](web-security.md), and exact versioned package receipts identify the implemented subset and actual verification. This is native product work, not an external Burp integration.
