# 0011: Workflow suite shell and shared retests

- Status: Accepted and implemented for 0.10.0
- Date: 2026-10-15
- Authority: Owner requested a top-left workflow-app selector, Web & API first, shared evidence/reporting/retesting, Parrot compatibility and complete regression checks.

## Decision

Retain the existing per-user desktop/local-server execution boundary and unified assessment store. Introduce three navigation apps: Web & API, Evidence, and Reporting & Retest. App selection changes the current task surface and in-tab return destination; every contextual handoff selects its owning app. No app has a separate assessment copy or target execution authority. Existing tools remain reachable through their workflow and the suite-wide finder.

Represent retests as additive versioned assessment metadata rather than a finding-status rewrite. Freeze the original summary and baseline references at creation, keep new evidence relationships and operator interpretation separately, and derive linked native test state from the authoritative investigation/run model. Require revision checks, bounded allowlisted fields, workspace-local references and idempotent creation. Preparation creates/reuses one investigation with no execution context or session authority; normal execution review still applies.

Enforce minimum occurrence, observed-evidence and completeness requirements before accepting reported resolution/still-present conclusions. These are operator assessments; no automatically verified remediation claim is introduced. Preserve original evidence, validation labels and findings. Propagate retests through JSON/HTML reports, export filtering and default redaction. A future unknown retest schema must fail safely.

Allow an explicit Linux installer `--system-qt` profile to reuse a complete installed Qt 6 WebEngine/QtPy stack. Probe the stack before installation and select a Qt 6 binding explicitly when Qt 5 is also installed. Keep the pinned engine installation as the default and keep Chromium sandbox/root-refusal/navigation policies unchanged. Native Parrot acceptance, not mocked window creation, determines platform qualification.

## Consequences and acceptance

The suite adds no target agent, multi-user tenancy, evidence synchronization or shared credential store. Tab-memory app/draft state is distinct from durable saved metadata. Imported content stays inert. Races and stale saves must preserve local drafts and avoid navigation based on superseded preparation. An ambiguous creation response must recover the same retest, and a linked incomplete test must not become resolution evidence.

[Suite workflow](../suite-workflow.md) documents the operator path and proof limits. [Suite verification](../suite-verification.md) records actual tests, packaging and native platform results separately from implementation claims. Broader workflow apps require a complete vertical workflow and their own acceptance evidence.

Native qualification exposed a blank-document helper-injection race and blocked xterm dynamic styles. Startup now waits for the protected blank document to finish loading. A per-document style-only CSP nonce is passed through xterm's scoped document override; ordinary inline styles/scripts remain blocked and bundled vendor bytes remain unchanged.
