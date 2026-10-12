# 0002 — Local initial product

Status: Accepted within the authorized implementation scope

Date: 2026-10-12

Decision maker: implementation agent under Brayden's explicit instruction to choose reversible engineering details and complete a usable initial product, with NorthGate available for bounded testing. This records implementation choices, not new licensing/distribution rights or independently granted lab authority.

## Context and options

The available environment has Python 3.12.14, SQLite and a browser test runtime. The product needs offline file imports, persistent evidence, interactive inspection, reversible identities and reports. No package install, paid product, or hosted service is needed for these outcomes. Workload, multi-user operation, commercial viability and production deployment remain insufficiently measured.

A hosted backend/database and frontend framework could support collaboration later but add deployment, dependencies and tenant isolation before that need is established. A browser-only store would simplify hosting but make persistence/recovery and bounded parsing harder to verify consistently. Select a small local application using Python's standard library, SQLite transactions and original HTML/CSS/JavaScript with SVG. Python's HTTP server is explicitly a local development/single-operator choice, not an Internet-facing production server.

## Implemented choices

- Bind only to `127.0.0.1`; reject other Host headers. Use an ephemeral session cookie, same-origin/nonce mutation checks, restrictive resource policy and whitelisted static files. Never provide an arbitrary path-fetch endpoint.
- Store an aggregate workspace snapshot atomically in SQLite schema version 1. Serialize operations in-process; an OS-held data-directory lock prevents two app processes from writing the same store. Reject unknown schema versions. Do not promise multi-process or distributed consistency.
- Import Nmap XML, Nessus v2 .nessus, Nuclei JSON/JSONL, ProjectDiscovery httpx JSON/JSONL, Linux iproute2 JSON bundles and `atlas-evidence/1` manual data. Supported mappings are bounded in the [format guide](../supported-formats.md). “Nexus” is provisionally Nessus, not a proven user correction or live integration.
- Choose Linux iproute2 address/route/neighbor output for the first substantive device adapter because its structured read-only output and synthetic contract are testable without credentials. NorthGate's connector returned an expired-certificate error, so lab platform availability and live output could not be inspected. Do not infer a lab platform from this choice.
- Keep source candidates separate across imports. Suggest shared labels/addresses within an address namespace; require a reasoned operator link. Keep decisions reversible, observation associations intact and differing values visible. Device/hop candidates can link; incompatible entity types cannot.
- Keep collection time, import time, source version, adapter version, testing position, location pointers, source digest and status/basis. Unknown metadata remains unknown. Scanner results stay source assertions. Raw files remain operator-held; selected normalized values/excerpts are best-effort scrubbed and bounded, not raw archives.
- Default exports withhold identifiers/free text. Offer explicit included-identifiers mode with preview, structured results, standalone SVG with evidence metadata, and printable HTML. Preserve conflicts and context outside selected filters where required to explain divergence.

## Limits and revisit triggers

No app encryption, multi-user identity, remote deployment, live scanner, mandatory agent, general vendor configuration parser or guaranteed secret removal is implemented. Display limits are 250 nodes and 600 relationships; full selected structured results remain exportable. File limit is 8 MiB and workspace limits are 10,000 entities/50,000 observations, which are guardrails rather than a performance guarantee.

Revisit snapshot storage and graph rendering when measured datasets make updates or inspection slow; hosting/tenancy when collaboration is requested; adapter coverage when authorized real outputs are available; at-rest controls before handling evidence that needs stronger protection. Product license and external contribution terms remain owner decisions. This ADR resolves initial mechanics from [0001](0001-evidence-first-imports.md) without superseding its broader direction.

Verification: [executed evidence](../verification.md). Runtime/library sources: [Python HTTP documentation](https://docs.python.org/3.12/library/http.server.html), [XML security guidance](https://docs.python.org/3.12/library/xml.html). No third-party runtime code is copied or bundled.
