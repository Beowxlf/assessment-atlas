# Assessment Atlas

A unified workspace for authorized security assessments that grows a network map from evidence gathered during an engagement.

**Status: runnable assessment and vulnerability workspace, version 0.6.0, October 14, 2026.** A local application with SQLite persistence, six legacy import formats plus inert web evidence, an interactive network/web map, identity reconciliation, assessment tracking and reports. Assessment Atlas and `assessment-atlas` remain working names. The GitHub repository is private. Native scoped crawling, request edit/replay/compare, verified authenticated crawl-and-audit, query/form/JSON checks, multi-position payloads, request/text-response interception, isolated JavaScript browser session handoff, codecs, token sample measurements and OpenAPI inventory are implemented. Native HTTP/2/3, scoped WebSocket capture/edit/replay and browser interception, owned HTTP/DNS callbacks, and twelve added scanner selections now feed the same assessment directly. Version 0.6 adds opt-in authenticated HTTPS hosting, an unprivileged Linux terminal, scoped embedded browser and evidence-to-finding handoff. No outbound device agent, external Burp bridge, paid component or CI workflow is included. Full Burp feature/scanner parity remains unfinished; see the [capability and acceptance matrix](docs/native-web-coverage.md).

Version 0.5.0 adds native [public vulnerability scans](docs/vulnerability-scans.md) with NVD/OSV/GHSA source criteria and separate KEV/EPSS context, direct existing-asset findings, offline JSON/SBOM inventory and explicit fixed public lookups. The [operator workspace](docs/operator-workflow.md) now has a discovery target table, prepared-context handoffs, six primary destinations and a searchable tool directory.

The destination is one workspace for topology, hosts and services, findings, access achieved, unanswered questions, testing history, and reports. Source-specific adapters should bring heterogeneous evidence into one common model. Offline imports are a first-class path; authenticated management collectors and optional agents are later possibilities.

Nmap discovery, service signatures, and OS fingerprints provide useful initial mapping evidence. A useful map does not require a complete physical topology. Each connection must explain what its evidence establishes and what remains unknown. Access to a router alone does not populate the workspace: configuration and operational output must be collected or imported.

## First complete workflow

Import Nmap XML and output from one supported device platform → reconcile device identities → inspect an interactive map → open evidence behind a connection → export the map and results with their limitations intact.

The first device platform is Linux iproute2 JSON; the stack is Python 3.12+ with standard-library SQLite/HTTP and a browser interface with a locally served MIT-licensed terminal library. The backend remains on loopback, with optional fixed HTTPS proxy hosting for one trusted operator account. See [Hosted operator console](docs/hosted-console.md) and [Third-party notices](THIRD_PARTY_NOTICES.md). See [ADR 0002](docs/adr/0002-local-initial-product.md), the [supported formats](docs/supported-formats.md), and the [roadmap](docs/roadmap.md). Product licensing remains an owner decision.

## Start the application

Extract the runnable package and double-click `Start.cmd` on Windows. Python 3.12+ is required; the launcher can also use the installed Codex Python runtime. On macOS/Linux run `sh start.sh`. Core import and ordinary web tools need no third-party Python runtime packages; native HTTPS interception additionally requires cryptography, and the isolated browser requires Node/Playwright/Edge. No Burp license/application is needed. HTTP/2/3 and WebSockets use the optional pinned engines in requirements-protocols.txt. See [native setup](docs/web-tools.md) and [protocol/callback workflows](docs/protocols-and-callbacks.md). Imports need no network; deliberate live tools contact only configured scoped targets.

From a terminal in the repository: `python -m atlas.server`. Open **http://127.0.0.1:8765**. The terminal must remain running; Ctrl+C closes the server, and saved workspaces remain available when it restarts. Use `--port 8766` if the default port is occupied. Do not expose or reverse-proxy this local server onto a network.

Create a workspace, record engagement scope, then open **Discovery** to import results or prepare scoped web enumeration. **Tools** and the header tool finder locate every native tool. **More workspace views** exposes the existing detailed views. Preview a file, supply testing position/network context when known, and save. Use **Network map** to inspect nodes/connections and reconcile identities with evidence. Add questions, tests, access and manual findings in **Assessment activity**; review scanner assertions in **Findings**. **Reports** provides JSON, map SVG and a printable HTML report; default exports withhold identifiers/free text, and you can preview before including them. Raw source bytes are never persisted or embedded: keep the originals in a protected evidence store and use their recorded hashes/references.

Version 0.1.1 has bounded actual NorthGate Nmap/Linux/manual verification and corrects scanner-forced host status: `up`/`user-set` is a configured assumption with unknown reachability, while open/filtered port results remain distinct. Historical observations stay intact; new derivations use adapter revision 2. See [Live validation](docs/live-validation.md).

The **synthetic example** demonstrates all six inputs without contacting targets. See [Getting started](GETTING_STARTED.md) for storage, backup, cleanup and capture instructions, and [Verification](docs/verification.md) for actual test evidence and limits.

## Native web tools

Open **Web workbench**, set exact owned origins/path scope and limits, then choose crawl/paths, request editing/comparison, selected-parameter tests, interception, authenticated browser or explicit scanner checks. Results feed the same evidence/map/review/reports. Imports never start collection. Metadata is the default; credentials/CA private keys stay transient. Schema 2 automatically backs up schema-1 data before upgrading and keeps unfinished runs interrupted after restart. [Setup, retention and recovery](docs/web-tools.md), [exact coverage and remaining work](docs/native-web-coverage.md), [security review](docs/web-security.md).

[Authenticated scans and advanced workflow](docs/authenticated-scans.md) explains transient cookie/bearer/login-sequence sessions, session-loss stopping, original checks, API requests, baseline/control finding evidence and exact limits. New findings feed the existing assessment directly. [Protocols, WebSockets and callbacks](docs/protocols-and-callbacks.md) explains the added transport, interaction correlation and canary checks. Schema remains 2; no database migration is required from 0.2.0/0.3.0. Web adapter revision 4 preserves older derivations.

## Verify a checkout

Run `python -m unittest discover -s tests -v`. These use synthetic fixtures and local temporary databases. Install requirements-web.txt and requirements-protocols.txt for the complete protocol/TLS fixture suite; optional protocol tests explicitly skip when their engines are absent. Browser checks are optional development tooling: start the local app, install/use Playwright with Microsoft Edge available, then run `node tests/ui.cjs`; see [Verification](docs/verification.md). Playwright is not a runtime dependency and is not bundled in the product.

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
| [Supported formats](docs/supported-formats.md) | Exact normalized fields, format boundaries and source documentation |
| [Getting started](GETTING_STARTED.md) | Launch, imports, evidence handling, backups and cleanup |
| [Verification](docs/verification.md) | Executed checks, package traceability and live-lab limits |
| [Live validation](docs/live-validation.md) | Restored connector, actual input coverage, workflow checks and the fault corrected |
| [Native web setup](docs/web-tools.md) | Collection, interception/browser dependencies, scope and recovery |
| [Capability matrix](docs/native-web-coverage.md) | Six areas, exact checks, broader inventory and unfinished acceptance |
| [Native verification](docs/native-web-verification.md) | Actual local/live/package evidence and limits |
| [Public vulnerability scans](docs/vulnerability-scans.md) | Sources, matching limits, public-query privacy, inventory and direct findings |
| [Operator workflow](docs/operator-workflow.md) | Discovery, tool finding, context handoffs and keyboard/mobile behavior |
| [Agent instructions](AGENTS.md) | Rules for future automated contributors |

## Licensing and sensitive material

No open-source license has been selected or granted by this repository. The owner must decide licensing before public distribution or external contribution terms are settled. Build original behavior; supported integrations and code reuse require separate compatibility review.

Never commit real engagement evidence, device configurations, credentials, or client identifiers here. A private repository is not an evidence vault. Use synthetic fixtures when implementation begins; see [Security](SECURITY.md).
