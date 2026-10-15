# Native web verification — 0.2.0

Verification date: October 12, 2026, America/Chicago. Environment: Windows, Python 3.12.14, cryptography 50.0.2, Node and Playwright 1.62.1, installed Microsoft Edge. This is a bounded original native implementation, not exhaustive Burp feature/scanner parity. [Capability/acceptance matrix](native-web-coverage.md) is the authoritative coverage boundary.

## Executed local acceptance

The full suite passes **52 tests**: preserved legacy adapters/evidence/history/security plus native crawl, exact origin/path/DNS pins, metadata/control-target exclusions, redirects, request/time limits, cancellation, partial results, request edit/send/compare, cross-workspace/auth boundaries, bounded payload baseline/variants, all eight response-check positive/negative controls and both differential indicators, event idempotency/collision, body/header/query redaction, HTTP proxy auth/edit/forward, actual HTTPS CONNECT and negative upstream CA validation, schema-1 exact backup/migration, interrupted-job handling and run-plan export redaction.

Actual Edge UI flows execute all six categories against owned local HTTP/TLS fixtures: crawl/paths, request edit/resend and response comparison, selected-parameter tests, explicit response checks, authenticated loopback interception with live editing/forwarding, and a **real isolated Edge HTTPS JavaScript login POST → cookie → authenticated API 200** through the native proxy. Sensitive fixture credentials are absent from persisted data; query/form/JSON parameter names are retained. Logical web map/report/run data and narrow-screen document width are checked. Source screenshots are synthetic and inspected; UI page errors/non-loopback UI requests are checked. The headless test flag affects only testing; the actual product opens an interactive isolated window.

The isolated browser's upstream TLS validates hostname and the configured owned fixture CA. Its trust exception is limited to the specific ephemeral Atlas proxy CA SPKI in that process, never a broad certificate-ignore flag or global trust change. No existing browser/Burp profile or proxy settings are replaced. No external Burp application/extension/direct pipe is included in this final direction.

## Bounded NorthGate acceptance

Actual native collection used exactly **five GET requests** to the owned existing operator origin: root/robots path enumeration (two), request resend/response comparison (two), and one response-check request. The existing public lab CA and hostname checks remained enabled. Every primary capture negotiated TLS 1.3 and had the unchanged previously verified peer-leaf digest. Actual data normalized into common graph/evidence/run records and passed redacted export. All target plans and real traffic remain in protected private evidence, outside Git/packages/screenshots.

Check derivations reuse one captured response; they are **not additional network requests**. The private receipt initially counted all transport observations as requests, then reconciled five primary captures and three derived check observations without repeating collection or rewriting saved evidence. New captures now carry source-capture correlation IDs. Tool findings remain indicators, not independently validated vulnerabilities.

No lab payload tests, browser interception, human login/MFA or Atlas deployment on a lab VM was performed. No lab VM, network, authentication or certificate changes occurred during this native testing. The RMM management agent/worker readback remained offline/unready; Atlas has **no endpoint agents**, and its native workstation-origin HTTPS collection does not depend on that RMM worker.

## Release/package integrity

The external delivery receipt identifies the exact committed revision, package SHA-256 and file-hash manifest, extracted-package tests/launcher, both browser workflows, synthetic screenshots, remote readback and preserved preview-data verification. A source check alone is not extracted-package evidence. Schema-2 startup creates a unique exact schema-1 backup before migrating existing data; old observations/IDs/history are retained. Existing 0.1.x packages/receipts remain historical and are not overwritten.

## Unqualified scope

No full competitor parity, independent scanner accuracy corpus, universal authenticated/SPA coverage, complete protocol interoperability/fuzz audit, large/concurrent workload, cross-platform browser matrix, accessibility certification or owner acceptance is claimed. HTTP/2/3, WebSocket flows, response interception/editing, streaming/chunked/binary request uploads, compressed-body analysis, advanced injection/authorization/out-of-band scanners, recorded login/session macros, combinatorial payload modes, token statistical analysis, dedicated codecs, custom extension/check APIs and broader commercial ecosystem remain unfinished. Exact hard bounds, optional dependencies, at-rest/backup and best-effort scrubbing limits are in [Setup](web-tools.md) and [Security](web-security.md).
