# 0004 — Transient authenticated native audits

Status: Accepted within explicit authorized implementation scope, October 13, 2026. Basis: Brayden requested native advanced Burp-style capabilities, including authenticated scans whose findings feed the assessment directly. This records reversible local implementation choices, not full competitor parity, public distribution, licensing or new external assessment authority.

## Problem and evidence

The 0.2.0 scanner analyzed one GET response. Its isolated browser could sign in but did not transfer that session to the scanner. Copying sensitive raw HTTP or storing credentials in assessment records would compromise the common evidence/retention model. Expired credentials could silently produce an anonymous scan and misleading coverage.

## Decision

Keep up to eight workspace-owned transient sessions in memory, expiring after one hour/restart; each run takes an independent bounded copy. Use exact origin-bound CookieJar instances and explicit headers. Support user-supplied GET/POST login sequences with hidden/JSON/header token extraction, a simple credential recipe builder and explicit isolated-browser cookie snapshots. Partitioned cookies/localStorage are not automatically transferred. No existing browser profile/proxy/trust settings change.

Require a genuinely protected success sentinel: anonymous control lacks it, authenticated guard returns the selected 2xx plus marker. Verify periodically, on unauthorized responses and before completion. At most two supplied-sequence refreshes; stop if a guard still fails. Count login/guard/probe/control requests against one request/time/rate budget and keep completed evidence on failure/cancellation. No auto-resume after restart.

Crawl-and-audit uses exact scoped GET links and explicit API/form/JSON requests. Active probes are separately selected. Original database-error and template-expression checks require baseline, neutral and repeat/different-product controls; markup/CORS/anonymous-content comparisons stay bounded indicators. Use declarative literal custom checks rather than arbitrary uploaded code. Imported OpenAPI schemas are inert inventories, never commands or authority.

Feed findings immediately through `atlas-web/1` into existing assessment entities/evidence/Findings/review/reports. Preserve primary capture, baseline/control IDs, source/version/time/vantage, authenticated context and scanner-reported status. Operator-edited downstream responses are separate manual derivations, retaining original upstream evidence/correlation and request counts. New fields require no schema change: schema 2 remains compatible with 0.2.0 data.

## Alternatives and consequences

Durably encrypting profiles would need a key/OS credential store and retention/recovery design; it is deferred. Importing browser storage wholesale would widen data/cross-origin exposure; snapshot only explicitly scoped cookies, with exact origin/path/expiry/secure behavior. Treating any 200 as a valid login would miss login-page/public responses; require a reviewed protected marker. Always relogging before each probe would increase account lockout/state risk; bound refresh and stop instead.

Transient process memory and best-effort scrubbed optional excerpts remain limitations; there is no forensic secure-memory-erasure guarantee. Login bodies are metadata even when body retention is selected. Session context does not prove each endpoint requires authentication or object-level authorization. Fixture accuracy and workflow checks are not independent general scanner qualification. WebSockets, HTTP/2/3, broad injection/transport/OOB coverage and full advanced-suite parity remain future native work, explicitly listed in the coverage matrix.

Verification: owned synthetic positive/fixed controls, auth failure/expiry/refresh, cross-workspace/origin/path/secure-cookie guards, secret-free database/exports, browser session handoff, finding review and text response edits. Exact executed release/package evidence is recorded in the versioned delivery receipt.
