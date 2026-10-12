# 0001 — Evidence-first import architecture

Status: Accepted for established product direction; implementation mechanics proposed

Date: 2026-10-12

Decision owner: Brayden

Basis: Brayden's product discussion requested a unified assessment workspace, normalized source-specific imports, offline operation, evidence-backed maps, optional collectors/agents, and staged expansion. This record captures that stated direction; publication does not claim separate approval of a schema, runtime or deployment.

## Context

Nmap discovery, fingerprints, DNS records, application paths, device configurations and operational output supply different kinds of evidence. They are useful together, but none alone establishes every network relationship. Router access only enables possible collection; a workspace needs actual imported or collected data. Identity reuse, vendor-specific formats, temporal changes and contradictions are the leading engineering uncertainties.

## Options considered

| Option | Tradeoff |
| --- | --- |
| Source-specific dashboards with separate models | Quick isolated views but duplicated identity/evidence logic and difficult cross-source reconciliation |
| Mandatory live collectors/agents first | Fresh operational data where authorized, but credential/platform burden and poor fit for offline evidence; does not solve provenance or identity by itself |
| Static graph or findings aggregator | Useful narrow output but leaves much of the requested assessment workspace outside the model |
| Common evidence model with source adapters and derived views | Supports the broader destination and offline work; requires careful normalization, reconciliation, history and adapter maintenance |

These tradeoffs are design reasoning, not benchmark results.

## Established direction

Use source-specific adapters feeding a common model of devices, interfaces, addresses, subnets, services, observations and typed relationships. Retain source/provenance, collection time, vantage, raw evidence references, observed/inferred/unknown status, conflicting evidence and identity uncertainty. Keep configured assertions distinct from operational observations. Offline import is first-class; later authorized collectors and optional agents can feed the same model.

The first complete workflow combines Nmap XML and output from one supported device platform, identity reconciliation, an interactive map, connection-evidence inspection, and map/results export. Later views extend to findings, access achieved, questions, testing history and reporting; the graph is one view of the unified workspace.

## Proposed implementation mechanics and consequences

The [logical model](../architecture.md) proposes append-preserving observations, reversible identity decisions, bounded adapter execution, derived snapshots and exports retaining evidence semantics. Exact schema, storage, transaction/deduplication policy, UI runtime, parser/platform, and deployment remain pending owner decisions and technical spikes.

This direction adds reconciliation and adapter upkeep costs, but preserves evidence across evolving views. It permits useful host/service maps before physical topology is known. Its boundaries exclude automatic scans from imported targets, unsupported identity merges, and execution of imported content.

## Verification and revisit triggers

No capability has been implemented or tested by accepting this direction. Use the [first-slice gates](../roadmap.md) to verify it once authorized implementation occurs. Revisit mechanics if supported source mappings cannot preserve semantics, reversible reconciliation becomes impractical, hostile inputs break isolation, or measured assessor workflows demand a different representation. A stack or platform selection requires its own ADR.

References: [Charter](../charter.md), [Security](../../SECURITY.md), [existing-tools research](../existing-tools.md).
