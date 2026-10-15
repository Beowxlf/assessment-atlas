# ADR 0008: Resumable investigation records

**Status:** Accepted within the owner's explicit implementation request, October 14, 2026.

## Context

The owner requested implementation of the resumable investigation workflow, authenticated testing and direct evidence-to-finding handoff, with restart and regression checks. Existing generic assessment records do not structurally connect questions, live runs, observations, interpretations and subsequent questions. Browser-tab drafts disappear on reload. Authentication intentionally remains transient.

## Decision

Add an investigation collection over existing entity, observation, import, run and record IDs. Keep SQLite schema 2 and add an independently versioned investigation envelope. Initialize missing collections additively without rewriting prior field values or identity decisions. Reject unknown investigation versions.

Use allowlisted persistent metadata, structured evidence relations, optimistic revisions and bounded history. Retain the current question/interpretation plus action/disposition history; do not duplicate every previous free-text value. Derive run snapshots on the server, retain outcome incompleteness, and create a queued run plus its investigation link in one save before any worker starts. Bind prepared tests to a reviewed investigation revision.

Keep credentials and live session state transient. Declared role/reference labels are metadata, while historical checked-session flags describe a particular run. Require existing protected-session verification for authenticated native audits and renewed authentication after restart.

Create one idempotent manual finding handoff per investigation, with selected linked observations, structured provenance references and explicit unvalidated proof limits. Preserve the ability to close negative/inconclusive work and create linked next questions. Apply export filtering/redaction to new objects and references.

## Alternatives

Continuing with free-text record references avoids a new collection but cannot enforce referential integrity or support reliable resumption. A replacement database/domain stack would require disproportionate migration and regression work without measured workload justification. Persisting entire workbench state would retain credentials and stale execution authority. The additive layer supplies the requested continuity while preserving the existing evidence model.

## Consequences and verification

Old workspace JSON hashes change when metadata is added; verify existing field values/IDs separately and preserve a stopped backup. Durability starts with explicit Save, followed by autosave of existing investigation fields. Finding-composition and next-question inputs remain transient until their action. This is a single trusted-operator workflow, not account, tenant or shell isolation.

The [workflow guide](../investigations.md) records behavior and limits. [Verification](../verification.md) and the exact package receipt record actual results. Synthetic functional acceptance does not establish human productivity improvement or real HTB connectivity; those remain separate roadmap gates.
