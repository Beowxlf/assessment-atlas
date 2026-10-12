# Project charter

## Purpose and vision

Assessment Atlas is Brayden's working concept for a unified workspace for authorized internal-subnet penetration tests and lab assessments. It grew from HTB CPTS web discovery and footprinting study: turn collected evidence into a progressively richer network map while keeping assessment context and unanswered questions visible.

Combine useful capabilities represented across discovery, network management, assessment tracking, and reporting tools through original implementation and extensible adapters. The long-term destination includes topology, services, findings, access achieved, questions, testing history, and reporting/export views over a common evidence model. The [existing-tools comparison](existing-tools.md) informs research; it is not a claim of feature parity or a complete market inventory.

## Outcomes

An assessor should be able to:

- Start with Nmap host discovery, service/OS evidence, and fingerprints, then enrich the workspace from device configuration and operational output.
- Reconcile identities without losing uncertainty, conflicting evidence, or historical observations.
- Inspect an interactive map and explain every connection using its source, time, vantage, meaning, and limitations.
- Distinguish topology, exposure, access achieved, findings, and pending tests rather than equating a visible service with a compromise.
- Export useful map/results for review and later reporting while retaining provenance and uncertainty.
- Add sources through adapters instead of rebuilding an engagement around each tool.

DNS records describe names/address relationships. Web directory discovery describes application paths. Directory traversal is a distinct vulnerability test, requiring its own evidence. These should eventually coexist in the workspace without being mislabeled as physical topology.

## Boundaries and principles

The map can be useful before physical wiring is known. Nmap signatures and fingerprints suggest hosts, services, OSs, and roles; they do not prove exact switch wiring or connectivity between another pair of hosts. Local neighbors, routed paths, physical adjacency, VLAN membership, and tested reachability are distinct relationship types.

Router access enables potential data collection; it does not automatically supply observations. Manual/offline import and later authenticated management interfaces or APIs feed the same model. Agents are optional. Passive observations and additional platform parsers are later stages.

For this initialization, only repository creation and governance publication are authorized. There is no software implementation, live scan, collector, device agent, or deployment. Future implementation requires a new task with a bounded slice. Avoid committing to universal parser coverage, production scale, a final stack, a delivery date, or a license without evidence and owner decisions.

## Success and evidence

The first complete product workflow is Nmap XML plus supported device output → identity reconciliation → interactive map → connection evidence → map/results export. Its measurable acceptance gates are in the [roadmap](roadmap.md). A parser demo, screenshot, or documentation commit alone cannot pass those gates.

Longer-term success means the same evidence model supports the broader assessment lifecycle without losing provenance or forcing mandatory agents. Customer demand, workload/scale, usability, performance, commercial viability, and cost are **Insufficient data** today. Resolve them through bounded assessor trials and measured fixture workloads rather than invented targets or dates.

Ownership and change authority: [Governance](../GOVERNANCE.md).
