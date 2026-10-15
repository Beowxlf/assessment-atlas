# Architecture decision records

Use an ADR when a choice affects evidence semantics, identity reconciliation, trust boundaries, storage, compatibility, adapter contracts, platform/stack selection, or a material recurring cost. Routine edits do not need an ADR. The [roadmap](../roadmap.md) holds unresolved decisions; [Governance](../../GOVERNANCE.md) defines authority.

Create `NNNN-short-title.md` from the [template](template.md). Keep IDs stable. Describe the problem, constraints and evidence before the decision; compare viable alternatives and consequences. Proposed records are not approval. The owner or explicitly delegated decision maker records acceptance with date and evidence of authorization. A record can capture already established product direction if it identifies its basis and does not claim approval of new mechanics.

Statuses: **Proposed**, **Accepted**, **Rejected**, **Superseded**. Accepted records should be preserved; a later ADR can supersede one with cross-links. Correct factual mistakes transparently rather than rewrite past rationale as though the change had always been decided.

| Record | Status | Scope |
| --- | --- | --- |
| [0001 — Evidence-first import architecture](0001-evidence-first-imports.md) | Accepted product direction; implementation mechanics proposed | Captures Brayden's stated evidence/import/common-model vision; selects no technology or parser |
| [0002 — Local initial product](0002-local-initial-product.md) | Accepted within authorized implementation scope | Python/SQLite/browser stack, six bounded inputs, Linux platform, storage/exports and actual limits |
| [0003 — Native web workbench](0003-native-web-workbench.md) | Accepted within explicit native implementation scope | Six bounded native workflows, scoped transport/interception/browser, schema-2 backup and unfinished parity acceptance |
| [0004 — Transient authenticated audits](0004-transient-authenticated-audits.md) | Accepted within explicit advanced native implementation scope | Transient sessions, protected guards, bounded refresh/audit, direct findings and control evidence; schema 2 remains compatible |
| [0005 — Protocols and owned interactions](0005-protocols-and-owned-interactions.md) | Accepted within explicit requested expansion | Verified pinned HTTP/2/3, scoped WebSockets, HTTP/DNS receipts, original canary checks and additive adapter-4 evidence |
| [0006 — Public advisory scans and operator handoffs](0006-public-advisory-scans.md) | Accepted within explicit requested implementation | Bounded NVD/OSV/GHSA correlations, separate KEV/EPSS context, copied assessment evidence, public cache and target/tool navigation |
| [0007 — Hosted operator console](0007-hosted-operator-console.md) | Accepted within requested hosted implementation | Fixed HTTPS operator access, unprivileged Linux execution, scoped embedded browser and selected evidence handoff |
| [0008 — Resumable investigations](0008-resumable-investigations.md) | Accepted within explicit requested implementation | Durable questions, revision-bound tests, evidence links, transient authentication and direct unvalidated finding handoff |
| [0009 — Dependable execution context](0009-dependable-execution-context.md) | Accepted within explicit requested implementation | Measured host/route context, transient reviewed authority, scoped identity and new-run continuation |
| [0010 — Operator-host desktop](0010-operator-host-desktop.md) | Accepted within explicit desktop/public-source request | Local VPN execution, per-user installation, optional selected-software computation and manual updates |
