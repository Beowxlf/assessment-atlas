# Atlas suite: Web & API first

Version 0.10.0 introduces a top-left app selector. The three delivered apps share one selected assessment and the same sources, observations, investigations, findings and report. App switching is navigation: it starts no requests, restores no authentication, and neither cancels nor restarts an existing test.

| App | Work performed |
| --- | --- |
| **Web & API** | Discover targets, continue investigations, prepare scoped native web/API tests, review authentication and execution context, and use the local terminal or isolated testing browser. Software advisory scans and all existing tools remain available. |
| **Evidence** | Import results, inspect provenance and claim levels, explore relationships, and retain notes and activity. |
| **Reporting & Retest** | Review source assertions and human findings, schedule evidence-backed retests, and export the assessment report. |

The selector remembers the last destination for each app and assessment in the current tab. Existing form drafts and transient web controls remain in their existing contexts. Saved investigations and retests survive closing and reopening Atlas; unsaved retest edits remain in this tab until Save. Selecting a different app never grants scope, host, route or session authority. Press **Ctrl/Command + Shift + L** for the app selector or **Ctrl/Command + K** to find a tool across the suite. Escape closes the selector and restores keyboard focus.

## Complete the Web & API workflow

1. Install and launch Atlas as the regular user on the Parrot/Kali host that runs the lab VPN. Select or create an assessment and record its scope. In **Web & API → Targets & discovery**, import discoveries or prepare a scoped test. Preparation only fills controls.
2. In **Investigations**, save a specific question and its expected execution host/interface. For authenticated work, save opaque role/reference labels, then establish and verify the actual session in the web workbench. Review the exact target, scope and route before starting a test. System routing does not prove that a VPN is healthy or reaches the intended lab.
3. Link the retained run and its supporting, contradicting or contextual observations. A cancelled, interrupted, failed or partial run remains incomplete. Review the interpretation and limits, then create a human finding draft from selected evidence.
4. Switch to **Evidence** to inspect the same observations and their original provenance. Switch to **Reporting & Retest → Finding review** to review the same finding. The report includes human finding records, investigations and retests alongside source assertions; finding-screen filters do not silently filter a report.
5. Choose **Schedule retest** on a finding. Save the question to freeze the original summary and baseline evidence references. Neither the original finding nor its evidence changes. **Prepare retest investigation** creates or reuses one linked question; it opens that investigation without executing a target request. Review the host/interface and re-establish authentication for the new test.
6. Collect fresh evidence, return to **Retests**, refresh collected results and add observation relationships. Save an explicit operator conclusion with its rationale and coverage limits. **Reported resolved** and **Reported still present** are operator assessments, never independent validation. Review and export the combined report.

## Retest integrity and recovery

Retests use additive `retests_version: 1` metadata, revision-checked saves, opaque idempotent creation tokens, an immutable original snapshot and separate baseline/new-evidence references. Preparation restores no session or execution authority. Unknown future retest versions fail safely. Old assessments acquire empty retest metadata without changing their existing evidence or schema version.

A reported resolution or still-present conclusion requires new supporting **observed** evidence for the original occurrence, imported after retest creation. Original baseline evidence, unrelated assets and inferred software advisories alone are insufficient. If a linked native test exists, reporting resolution also requires its latest run to be complete and supporting evidence from that run. These checks establish minimum provenance and completeness, not the truth or full coverage of a remediation claim. An operator must still evaluate response semantics, identity, role and scope.

An interrupted native test is prepared as a new run under the existing investigation execution rules; it is never resumed with old credentials or authority. The original incomplete run remains inspectable. Manual and external checks can also supply evidence with their original provenance and declared limits.

If another tab updates a retest, a stale save fails and preserves the local edits. Use **Compare saved version** before explicitly discarding them with **Discard local edits and reload saved retest**. An ambiguous first-save failure retries the same creation request, recovers its original result, and then saves newer local edits rather than creating duplicate retests. If edits change while preparation is pending, Atlas retains them and stays in Retests for review.

## Reports and custody

Reports contain the unchanged original finding plus a separate retest interpretation, baseline/new evidence relationships, linked test completeness and proof limits. Default identifier-redacted exports withhold retest free text and execution context just as they do investigation and native capture context. Scope-filtered exports trim references to omitted observations and retain omission counts. Exporting identifiers is a deliberate disclosure choice; inspect the preview before sharing it.

This release provides the suite shell and a complete initial Web & API path. Active Directory, cloud and other workflow apps are future work and do not appear as working choices. It does not add shared credentials, multi-user tenancy, background synchronization, automatic remediation verification or full scanner parity. See [suite verification](suite-verification.md), [desktop setup](desktop.md), [execution context](execution-context.md) and [ADR 0011](adr/0011-suite-shell-shared-retests.md).
