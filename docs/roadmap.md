# Roadmap, owner decisions, and risks

For the **proposed next product direction**, see [Atlas: from observations to defensible findings](product-vision-and-roadmap.md). It prioritizes resumable investigations, connected evidence and dependable execution, with sequenced workflow acceptance gates. The stages and decisions below retain the original delivery history and governance baseline.

**Original planning baseline: October 12, 2026; updated October 14, 2026 after authorized native extensions.** Version 0.5.0 now extends the first runnable workflow and bounded assessment/reporting features. The stages below preserve the broad destination rather than claim competitor parity or completion of future coverage. No delivery dates, staffing or budget are promised; this roadmap is not itself authorization for live assessments.

## Current evidence and decisions

The governance bootstrap was published as `b2ba96c4b5e16d1801f85cf87e3758880762aafb`. The owner then authorized implementation and reversible stack/platform choices. [ADR 0002](adr/0002-local-initial-product.md) resolves D1/D2 for the initial product: Linux iproute2 bundles, Python 3.12+, SQLite and an original browser/SVG interface. It also records bounded local storage/export mechanics for D4. Native scoped web collection is now implemented under explicit subsequent owner direction; no endpoint agent or external Burp bridge is added. [ADR 0003](adr/0003-native-web-workbench.md) and the [capability/acceptance matrix](native-web-coverage.md) preserve broad native scope and unfinished work. [ADR 0004](adr/0004-transient-authenticated-audits.md) and [ADR 0005](adr/0005-protocols-and-owned-interactions.md) record implemented transient authenticated audits, protocols, WebSockets and owner-controlled callbacks. D3 licensing remains open; real-evidence handling must fit the chosen OS access/retention model. Broader workload thresholds, adapter maintenance capacity, security contact and repository enforcement remain owner/product decisions.

The first workflow, six adapters and assessment features are implemented and locally exercised with synthetic evidence; [Verification](verification.md) records actual results. The expired connector certificate has been renewed with verified service/timer recovery. Actual bounded Nmap/Linux/manual intake and the complete private workflow passed; [Live validation](live-validation.md) records the evidence and Nmap assumption correction. Nessus/Nuclei/httpx remain synthetic-only, and agent-backed/fleet coverage remains unverified. The remaining stages below are future expansion; the initial product is not a claim that all later parser, passive, collector and integration work is complete.

## Staged delivery

| Stage | Outcome | Exit evidence |
| --- | --- | --- |
| 0 — Governance bootstrap | Coherent vision, authority, evidence principles, security policy and decision process | Reviewed documents, valid cross-links, initial Git commit and remote readback; no product capability implied |
| 1 — Resolve risky choices | Select one device platform/input bundle and stack for the first workflow; evaluate reconciliation and import semantics | Owner-recorded decisions, synthetic fixture plan, supported input/version boundary, security/storage design, and bounded technical spike results |
| 2 — First complete workflow | Nmap XML plus selected device output → reconciliation → interactive map → evidence inspection → export | Every first-slice gate below demonstrated on an identified commit with synthetic inputs |
| 3 — Extend evidence coverage | More vendor/platform importers, DNS/web-discovery import paths and passive observations | Versioned mappings, synthetic contract fixtures, conflict/time behavior, support matrix, maintained adapters and unchanged evidence invariants |
| 4 — Optional live collection | Authenticated management/API collectors; optional agents only if justified | Approved collection contracts, scope enforcement, credential isolation, resource limits, cancellation/activity evidence, cleanup, and offline-path regression evidence |
| 5 — Unified assessment lifecycle | Findings, access achieved, questions, testing/retest history and reporting integrations over the common model | An assessor completes an engagement narrative across those views; exports preserve evidence boundaries, adapter rights and maintenance are reviewed |

Later research can overlap once authorized, but a later feature must not bypass prerequisite security or evidence contracts. The broader destination remains the unified workspace; staging sequences it rather than shrinking it into a graph-only product.

## First-slice acceptance gates

Before implementation, document the selected platform, command-output bundle, supported versions, export formats, representative fixture size, and resource/performance targets justified by a measured workload. **Insufficient data** currently prevents credible performance or capacity promises.

| Gate | Required demonstration |
| --- | --- |
| G1 — Import and useful initial map | Nmap-only fixture shows expected devices/services and source-attributed fingerprints without requiring physical topology. Import a selected device-output fixture and verify its expected observations and typed relations against a manually reviewed truth table. Unsupported variants yield explicit diagnostics. |
| G2 — Provenance and uncertainty | Every displayed relationship opens its source location, raw reference, collection/import time, vantage, status and evidence basis. Missing metadata stays unknown. Configured/operational contradictions and older/newer observations remain inspectable. |
| G3 — Identity integrity | Synthetic cases include reused IP, repeated hostname, overlapping address spaces, multi-interface device and conflicting identifiers. No automatic merge occurs solely by IP/name. Review, accepted merge, keeping candidates separate, and undo/split preserve observations and recorded rationale. |
| G4 — Interactive inspection | Assessor imports both inputs, reconciles candidates, selects a connection, inspects evidence, filters relationship types/snapshots, and sees unknown/conflicting states. Verify essential workflow by keyboard and check readable legend/labels; a screenshot alone is insufficient. |
| G5 — Import safety and repeatability | Repeat identical import under the documented deduplication policy; changed input retains history. Malformed/oversized input and hostile XML/text neither execute content nor cause outbound requests. Failed import leaves the prior engagement intact under the declared transaction/partial-result policy. Verify persistence after closing/reopening. |
| G6 — Export and cleanup | Export the selected map and structured results; verify every exported relation retains type, status, time/vantage, provenance references and conflicts/limitations, with a redaction manifest and usable approved evidence references. Reconcile export with selected view; exercise deletion of workspace artifacts and temporary outputs under the retention policy. |

For each gate, record commit, environment, fixture identifiers/digests, steps, actual outcome, failures and limitations. Product behavior is not implemented until the relevant workflow exists, and not verified until demonstrations occur. Local synthetic demonstrations for G1–G6 are recorded in [Verification](verification.md), with raw-file handling, platform, scale and accessibility limits. Live-lab verification and a human assessor acceptance trial remain separate evidence.

## Unresolved owner decisions

Brayden owns these decisions unless he delegates them explicitly. The table preserves the original decision questions; initial D1/D2 and reversible D4 choices are now recorded above and in ADR 0002. Other answers are not assumed.

| ID | Decision | Evidence needed / when needed |
| --- | --- | --- |
| D1 | First device vendor/platform, versions and exact output bundle | Available authorized lab data and synthetic reproducible examples; before adapter spike/support claims |
| D2 | Runtime, UI, persistence, deployment/hosting and tenancy model | Compare small viable options against offline operation, evidence isolation, portability, maintenance and first-workflow needs; before implementation |
| D3 | Product license and external contribution/distribution terms | Owner intent and dependency/integration rights review; before external code intake or public distribution |
| D4 | Evidence storage, credentials, access control, retention, backup/deletion and export formats | Data sensitivity and user workflow; before real evidence or any live collector |
| D5 | Initial workload and measurable usability/performance thresholds | Bounded fixture measurements and assessor trial; before first-slice acceptance |
| D6 | Supported adapter lifecycle and ownership | Maintainer capacity, version range, fixture upkeep and deprecation contract; before claiming each adapter supported |
| D7 | Security contact and repository enforcement | Owner's private reporting channel and collaboration needs; before broader contributions; protection/CI/private reporting not configured by bootstrap |

## Risk register

| Risk | Trigger / consequence | Planned response and revisit point |
| --- | --- | --- |
| Identity conflation | Address/name reuse, NAT, overlapping namespaces, cloned identifiers → false merges and misleading map | Reconciliation spike, adversarial synthetic cases, reviewable reversible decisions; revisit before storage schema acceptance |
| Parser variation | Platform versions, localization, partial output → false or missing links | Bound support per format/version, preserve diagnostics and raw references, fail transparently; revisit every adapter change |
| Contradictory/time-varying evidence | Config intent differs from live state; stale scan → overstated reachability | Append sourced observations, expose snapshot/conflict rules and vantage; revisit before UI/export acceptance |
| Adapter maintenance | New vendors outpace owner capacity → unsupported coverage | Require an owner and synthetic contracts, cap concurrent coverage, publish deprecation; revisit before each expansion |
| Sensitive evidence or hostile input | Config secrets, embedded instructions, XML/HTML payloads → disclosure or execution | Controlled storage, synthetic repository fixtures, bounded parsers and export redaction; revisit before any real-data use |
| Vision/effort mismatch | Broad product ambition without workload, budget or user trials → overcommitment | Finish a vertical workflow, measure usefulness, retain extensible boundaries; reassess after first-slice trial |

Governance: [decision authority](../GOVERNANCE.md). Architecture changes: [ADRs](adr/README.md).

## Implemented 0.5.0 extension

The owner requested public vulnerability scans and a simpler operator workflow. [ADR 0006](adr/0006-public-advisory-scans.md) records fixed public NVD/OSV/GHSA applicability, separate CISA KEV/FIRST EPSS context, reviewed existing-asset inventory, immutable direct findings and a bounded local cache. Discovery/Tools now provide target inspection, prepared-context handoffs and a task/name directory. [Vulnerability coverage](vulnerability-scans.md) and [operator acceptance](operator-workflow.md) retain unknown applicability, source availability, explicit query disclosure and heuristic/browser versus real-operator limits. Broader authenticated package collection, distribution/backport-aware version semantics, universal SBOM coverage, bulk database mirroring, independent scanner accuracy benchmarks and competitor parity remain future work.

## Hosted operator extension — 0.6.0

The owner requested and received opt-in private Ubuntu hosting, an embedded execution terminal/browser and evidence-to-finding handoff; [ADR 0007](adr/0007-hosted-operator-console.md) records the resulting single-operator trust model. [Pentest audit](pentest-workflow-audit.md) separates delivered fixture workflows from the unfinished host connector, real HTB route/target trial, independent scanner accuracy, large-inventory pagination, broader clients and operator/tenancy qualification. Earlier hosting exclusions describe prior releases.
