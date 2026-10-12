# Architecture decision records

Use an ADR when a choice affects evidence semantics, identity reconciliation, trust boundaries, storage, compatibility, adapter contracts, platform/stack selection, or a material recurring cost. Routine edits do not need an ADR. The [roadmap](../roadmap.md) holds unresolved decisions; [Governance](../../GOVERNANCE.md) defines authority.

Create `NNNN-short-title.md` from the [template](template.md). Keep IDs stable. Describe the problem, constraints and evidence before the decision; compare viable alternatives and consequences. Proposed records are not approval. The owner or explicitly delegated decision maker records acceptance with date and evidence of authorization. A record can capture already established product direction if it identifies its basis and does not claim approval of new mechanics.

Statuses: **Proposed**, **Accepted**, **Rejected**, **Superseded**. Accepted records should be preserved; a later ADR can supersede one with cross-links. Correct factual mistakes transparently rather than rewrite past rationale as though the change had always been decided.

| Record | Status | Scope |
| --- | --- | --- |
| [0001 — Evidence-first import architecture](0001-evidence-first-imports.md) | Accepted product direction; implementation mechanics proposed | Captures Brayden's stated evidence/import/common-model vision; selects no technology or parser |
