# Verification and delivery limits — historical 0.2.0 baseline

Current 0.5.0 source verification: **104 Python tests passed**, including 19 advisory/cache/matching/scan/API tests, with optional engines installed on Windows/Python 3.12.14. Six real Edge workflows cover legacy intake, native web tools, authenticated audits, protocols/callbacks, direct vulnerability findings and operator discovery/tool handoffs. Advisory tests cover inert atomic imports, malformed inputs, CVSS/EPSS bounds, CPE environment/unknown applicability, SemVer/opaque versions, query identity/digest binding, alias grouping, cancellation, public-query disclosure/private-field exclusion, direct asset findings, immutable evidence and redacted/full reports. [Vulnerability scope](vulnerability-scans.md), [operator workflow](operator-workflow.md) and [protocol qualification](protocols-and-callbacks.md). Exact extracted-package tests, public source availability, source revision/hash and preview preservation are recorded in the versioned delivery receipt.

The remainder preserves earlier verification. Verification date: October 12, 2026. Environment: Windows, Python 3.12.14, Edge headless via Playwright. The general regression suite and packaged examples are synthetic. A separate actual NorthGate workflow is recorded in [Live validation](live-validation.md). Package manifests identify exact revisions/file hashes; external receipts record extracted-package tests. Live raw evidence is never bundled.

## Executed local checks

- Python importer/store/API tests cover the six fixture formats and expected semantic counts, current/legacy httpx fields, source metadata gaps/overrides, UTF-8 BOM acceptance, XML entities/custom DTD rejection, malformed/deep/oversized input, invalid manual references, best-effort secret scrubbing, no importer network/subprocess execution, deduplication, concurrent identical imports, unchanged state on failed import, changed-result history, namespace separation, reversible identity linking and conflicts, compatible entity types, persistence after reopening, schema-version rejection, activity/finding review history, report escaping, selection/redaction, and deletion.
- Local HTTP tests exercise create → preview → import → export → delete and reject unauthenticated requests, missing mutation nonce/origin, cross-origin requests, unrecognized Host headers and arbitrary file paths. Response policy/cookie headers are checked.
- The Linux capture helper contract uses mocked command results to verify its fixed read-only command set, ten-second timeouts, output parseability, and refusal to overwrite a file. This is not a live Linux execution test.
- Real-browser automation uses direct file selection for all six inputs, keyboard evidence activation, identity link/undo, assessment activity and finding review, reload persistence, repeat import, hostile XML rejection, redacted/included export previews, JSON/HTML/SVG downloads and map filters. Desktop (1440×1000) and mobile (390×844) screens are captured; page errors and non-loopback requests are checked. Actual screenshots were visually inspected, and oversized arrows, map legibility and an overlong suggestion panel were corrected. No whole-document horizontal overflow was observed at the tested narrow viewport.
- Standalone SVG output was parsed as XML. Source whitespace/syntax, internal links and package file hashes are checked before delivery. No CI, branch-protection enforcement, independent security audit, accessibility certification, or user acceptance trial is claimed.

The earlier 0.1.1 source suite passed **35 tests**, including forced/missing Nmap discovery and a forced-up host with only filtered ports. Version 0.1.0 passed 31 tests. The final package receipt separately records exact extracted-package validation; source checks alone are not package launch evidence.

## Measured synthetic workload

In the earlier 0.1.0 verification, one local generated Nmap-shaped input with 1,000 repeated-address host candidates produced 2,000 entities and 3,000 observations, persisted and projected in **0.590 seconds** in the recorded run. It also exercised bounded suggestions without merging repeated identifiers. This measures a single Python/store operation, not browser usability at that size, sustained throughput, memory limits, concurrent operators or the full capacity guardrails.

The UI displays at most 250 map nodes/600 relationships and 500 evidence rows, with visible limits and filters. Suggestions show at most 200 pairs with bounded candidate comparisons; other identities remain selectable manually. The workspace guardrails (10,000 entities/50,000 observations) are not verified capacity promises.

## NorthGate and live evidence

The prior certificate blocker is resolved under explicit owner authorization. Unchanged-CA TLS, actual connector grants/contracts, 11 affected services, both audit/maintenance timers, protected rollback integrity and negative unauthenticated access were verified. Actual Nmap 7.95, two Linux iproute2 6.1.0 snapshots and corroborated manual evidence passed the private import/map/evidence/reconciliation/export/persistence workflow, including actual server restart. See [Live validation](live-validation.md) for counts, the corrected host-assumption bug, interrupted refresh/recovery details and exact limits. No live Nessus/Nuclei/httpx run, human login/MFA retest or endpoint-agent recovery is claimed.

## Gate interpretation

G1–G6 from the [roadmap](roadmap.md) have local synthetic workflow demonstrations: multi-source intake; provenance and unknowns; identity integrity/undo; interactive/keyboard inspection; bounded non-executing imports and persistence; exports and deletion. They are bounded by the tested input shapes and workstation. Raw-byte storage is intentionally replaced by operator-held originals with original-input digests and retained normalized source excerpts. Historical contradictions are flagged as divergent values, not adjudicated automatically. Collection staleness/time intervals, general physical adjacency/VLAN inference, universal vendor coverage and production deployment remain future work.

## Reproduce and package

From the checkout root run `python -m unittest discover -s tests -v`. Start the app with a synthetic data directory: `python -m atlas.server --data-dir work/browser-data --no-open`. For browser checks, use an installed Playwright package and Microsoft Edge, then `node tests/ui.cjs`. Optional environment settings are `ATLAS_PLAYWRIGHT_MODULE` (module path), `ATLAS_UI_URL` (loopback app URL), and `ATLAS_UI_OUTPUT` (screenshots/downloads/receipt directory). Playwright supplies test tooling and the optional native browser runtime; core offline import/report workflows do not require it.

To build a source/runnable ZIP from a clean committed revision: `python tools/package.py /new/path/assessment-atlas-0.2.0.zip`. It refuses an existing output, uses committed Git content, includes the revision/file-hash manifest and verifies archive integrity. Extract elsewhere, run the suite and app from the extraction, and exercise the browser workflow before delivering. Preserve sensitive workspace data separately; the archive contains only source, docs and synthetic fixtures.

## Material remaining limits

Single workstation/operator only; OS account/disk controls rather than app encryption; Python/browser and optional native TLS/browser dependencies required. Native scoped web tools are implemented, with exact support/limits in [Coverage](native-web-coverage.md); no authenticated guest-management collector or endpoint agent is provided. Linux bundles remain the device-output platform; no universal tool/version matrix, remote collaboration or reporting-service connector is claimed. Results exports are not workspace-restore files; no guaranteed secret detection or forensic erase. Long excerpt truncation and unknown/unmapped fields are disclosed. Source flags and a review status never establish independently validated impact. Product license and external contribution terms remain undecided.

## Native web extension of verification

The current 0.2.0 source suite passes 52 tests, and actual UI workflows exercise all six native categories, including a real isolated Edge HTTPS login POST/cookie/JavaScript API session. This does not establish all-feature/scanner parity. [Native verification](native-web-verification.md) records named environments, exact local/live/package coverage and material limits. Earlier 0.1.x results above are historical; the newer external package receipt is authoritative for its exact committed artifact.

## Hosted console verification — 0.6.0

October 14, 2026: the full suite passed 120 tests on Ubuntu 22.04.5/Python 3.12.15 with zero skips. Windows/Python 3.12.14 passed with six Linux-only skips; the Linux PTY/profile cases were separately exercised. Node 22.23.3, Playwright 1.62.1/Chromium 151, cryptography 50.0.2, h2 4.4.1, aioquic 1.6.1 and wsproto 1.3.2 were installed/verified.

Six existing Edge workflows plus the embedded console and live private HTTPS workflow passed. The hosted check covered authentication/anonymous denial, actual service PTY and ordered input, route-checked HEAD intake, sandboxed browser input, actual fixture authentication, native evidence references, a visible manual finding, authenticated audit findings, mobile width and logout rejection. Labelled hosted fixture assessments are retained; the original assessment body hash was checked unchanged. No real HTB VPN/target, global trust installation, independent scanner benchmark or human operator trial is claimed.

A separate invented-inventory database on Ubuntu exercised five verified public NVD/OSV/priority queries, retaining 88 grouped leads and three uncertain environmental/version candidates with a partial outcome, zero target probes and no production data changes. See [Pentest audit](pentest-workflow-audit.md) and [Hosted console](hosted-console.md). Exact-package receipts give the final revision/hashes and verification logs.

## QoL verification — 0.6.1

October 14, 2026: real Edge acceptance exercises terminal/browser target preparation without execution, finding search/status/severity/type filters and independent reports, Enter/arrow finder navigation, recent tool names, workspace-separated transient drafts, review refresh and out-of-order workspace responses, edits during saving, existing-draft protection, scoped page navigation/rejection, path-preserving authenticated preparation, explicit stop and 390px reflow. The exact packaged-revision receipt records full regression and Ubuntu deployment checks. No real HTB route/target or independent usability/accessibility qualification is added. Schema remains 2.
