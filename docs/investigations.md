# Resumable investigations

Version 0.7.0 connects a question, its tests, selected evidence, interpretation and next action inside the existing assessment. It supports authenticated native audits and a direct handoff into a manual finding. Negative and inconclusive investigations can close without creating findings.

Version 0.8.0 adds [dependable execution context](execution-context.md): saved host/interface expectations, a fresh measured route/session check before linked tests, and reviewed new-run continuation of incomplete tests. Existing questions retain their prior fields; review and save execution context before launching their next test. **Prepare again** restores no credentials, request bodies or authority.

## Work through a question

1. Choose an assessment and open **Investigations**. Select **New investigation**, enter the question, and optionally select its existing identity, objective and boundaries.
2. Choose anonymous or authenticated access. For authenticated work, enter a role label and an opaque reference such as `ref:test-account-a`. These describe intended context; they are not credentials or proof of the role's access.
3. Select **Save draft**. The question now lives in the assessment database. Subsequent edits to investigation fields save after a pause, with visible saving/saved/error feedback. Save explicitly before closing the browser; the browser warns while edits or a save are pending. Ctrl/Command+S saves while an investigation field is focused.
4. Select **Prepare a web test** or **Prepare an authenticated test**. Atlas saves current edits, prepares a source-derived URL where available, clears previous authentication and authorization controls, and opens the appropriate native workbench. Review the exact target, scope, limits, host/vantage and authority. Authentication, authorization and request secrets are cleared before navigation reveals the workbench, including while a status refresh is delayed. Preparation never starts collection.
5. For an authenticated investigation, establish a transient session using the existing [protected-session workflow](authenticated-scans.md), then explicitly start the scanner or payload matrix. A saved account reference cannot satisfy this requirement. Anonymous investigations can also use request replay. Successful starts link their run automatically before execution; unrelated retained runs can be linked manually.
6. Return to the investigation and **Refresh collected results**. Inspect the run and observation provenance, then link selected observations as supporting, contradicting or contextual evidence. Completed, failed, partial, cancelled and interrupted execution remain separate from the investigation's decision.
7. Record whether the hypothesis is supported, refuted in the tested context, inconclusive or still undecided. Explain the interpretation and limits, and save the next useful action. Work status is separate: open, in progress, blocked or closed.
8. Select observations to include in a finding. Supply its title, observed behavior, impact and proof gaps, then choose **Create finding draft from linked evidence**. The manual finding appears in **Findings**, assessment activity and reports with stable evidence and investigation references. **Open linked finding** moves to that specific finding. A repeated click cannot create a duplicate.

Alternatively, **Save and create next question** creates a linked investigation carrying the objective, subject and declared access labels. It carries no credentials or session. The workspace's continuation panel lists recent open questions with their interpretation and next action; closed questions remain searchable in Investigations.

## Restart and conflict behavior

Saved investigation fields, evidence links, run references, finding handoffs and next-question links survive browser reload and application restart. Drafts remain separated by assessment. New drafts require their first explicit Save; finding-composition and next-question inputs are transient until their creation action. Ordinary legacy assessment-record drafts retain their existing tab-memory behavior.

Active collection is never resumed automatically. On restart, queued/running jobs become interrupted and retain completed evidence. Linked snapshots show that incompleteness. Cookies, bearer tokens, login bodies, browser/terminal buffers and proxy CA private keys are not restored. Authentication must be deliberately re-established before a new authenticated run.

Investigation edits use revision checks. A second tab cannot silently overwrite newer work. Conflicts preserve local text and offer **Compare local edits with saved draft** and **Discard local edits and reload saved draft**. Review the comparison before discarding. Linked-run/evidence/finding operations also respect revisions, and edits made while a link request is pending are saved afterward. Test preparation is bound to its reviewed investigation revision; changing the question or context requires preparation again before execution. A successful run link advances only that preparation's own revision.

## Persistence and evidence boundaries

The workspace JSON adds `investigations_version: 1` and an `investigations` collection with `atlas-investigation/1` objects. SQLite's main schema remains 2. Old workspaces receive the missing fields on opening; their prior values and IDs are preserved. The serialized whole-body hash changes because metadata is added. Preserve a stopped-database backup before upgrades; results exports are not restorable database backups. Unsupported investigation versions fail safely.

Run snapshots are derived by the server from a small allowlist: tool kind, outcome/completeness, timestamps/counts, sanitized URL structure, scope origins, vantage, namespace, limits and supported typed-operation context. Historical authentication records contain only mode, a checked-session flag and generation count where available. They describe that run, not a currently usable session or demonstrated authorization. Credentials and arbitrary request configurations cannot be submitted as investigation fields. Free text still needs operator review; pattern scrubbing is not a guarantee that every secret is recognized.

Evidence points to existing observations and their source artifacts. Linking does not change their claim status or retain additional original bytes. The existing capture mode, truncation, raw-retention and protected-original rules still apply. A scanner indicator stays an indicator. A supported decision or completed run does not prove exploitation, object access or impact. Findings created here are explicitly operator-authored and not independently validated; default severity is unrated.

Default JSON/HTML exports withhold investigation questions, objectives, interpretations, next actions, account labels and snapshot context alongside existing free-text redaction. Included exports retain those fields deliberately. Selection filters trim unavailable evidence and related references and disclose omission counts. History records actions, revisions, changed field names and dispositions; it is not a full copy of every previous free-text revision.

Limits are 200 investigations per assessment, 100 linked runs and 200 linked observations per investigation, 500 history events per investigation, and 50 linked next questions. The existing workspace and run limits remain. At a limit, start a linked question or separate assessment as appropriate; no discarded history or silent automatic execution is implied.

## Verification

[Backend tests](../tests/test_investigations.py) exercise persistence, old data, concurrent/stale edits, reference ownership, safe snapshots, atomic linkage, handoff idempotency and exports. [API checks](../tests/test_investigations_api.py) terminate and restart real hosted processes around a synthetic authenticated audit. [Edge checks](../tests/investigation-ui.cjs) exercise the visible workflow, autosave, delayed updates, conflicts, finding navigation and narrow-screen layout.

See [verification](verification.md) and the exact release receipt for executed environments/results. These are synthetic functional checks, not an HTB VPN assessment, independent security review or operator usability benchmark. The broader [product roadmap](product-vision-and-roadmap.md) remains proposed beyond this first slice.
