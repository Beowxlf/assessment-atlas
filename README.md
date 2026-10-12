# Assessment Atlas

A unified workspace for authorized security assessments that grows a network map from evidence gathered during an engagement.

**Status: governance and product definition only, initialized October 12, 2026.** No application, parser, collector, agent, automated test suite, CI workflow, or release is included. Assessment Atlas and `assessment-atlas` are working names. Repository hosting is private by default; this is not a decision about future product deployment.

The destination is one workspace for topology, hosts and services, findings, access achieved, unanswered questions, testing history, and reports. Source-specific adapters should bring heterogeneous evidence into one common model. Offline imports are a first-class path; authenticated management collectors and optional agents are later possibilities.

Nmap discovery, service signatures, and OS fingerprints provide useful initial mapping evidence. A useful map does not require a complete physical topology. Each connection must explain what its evidence establishes and what remains unknown. Access to a router alone does not populate the workspace: configuration and operational output must be collected or imported.

## First complete workflow

Import Nmap XML and output from one supported device platform → reconcile device identities → inspect an interactive map → open evidence behind a connection → export the map and results with their limitations intact.

The first device platform, technology stack, deployment model, and license remain undecided. See the [roadmap and decision register](docs/roadmap.md) for proposed gates and owner decisions.

## Read the project

| Document | Purpose |
| --- | --- |
| [Charter](docs/charter.md) | Vision, boundaries, user outcomes, and success criteria |
| [Governance](GOVERNANCE.md) | Ownership, contribution, review, change, and release decisions |
| [Contributing](CONTRIBUTING.md) | Practical contribution and adapter requirements |
| [Security](SECURITY.md) | Scope, sensitive evidence, import safety, and vulnerability reporting |
| [Architecture and evidence model](docs/architecture.md) | Common entities, typed relationships, provenance, and trust boundaries |
| [Roadmap](docs/roadmap.md) | Staged delivery, acceptance evidence, unresolved decisions, and risks |
| [Existing tools](docs/existing-tools.md) | Representative source-backed comparison and integration boundaries |
| [Decision records](docs/adr/README.md) | Decision process, template, and initial direction |
| [Agent instructions](AGENTS.md) | Rules for future automated contributors |

## Licensing and sensitive material

No open-source license has been selected or granted by this repository. The owner must decide licensing before public distribution or external contribution terms are settled. Build original behavior; supported integrations and code reuse require separate compatibility review.

Never commit real engagement evidence, device configurations, credentials, or client identifiers here. A private repository is not an evidence vault. Use synthetic fixtures when implementation begins; see [Security](SECURITY.md).
