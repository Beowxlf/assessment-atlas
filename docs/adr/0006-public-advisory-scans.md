# 0006 — Public advisory scans and operator handoffs

**Status:** Accepted within explicitly requested implementation scope, October 14, 2026.

## Context and authority

The user requested native vulnerability scans using public databases with direct assessment intake, then simpler discovery/enumeration and tool organization using Cobalt Strike/Burp Suite references. This authorizes implementation and local verification; it does not authorize arbitrary target scans, public publication, purchases, competitor code reuse or identity merges.

## Decision

Combine NVD CPE/CVE applicability and OSV package advisories (including GHSA) with separate KEV/EPSS prioritization facts. Support inert offline JSON and explicitly disclosed fixed-origin public queries. Keep the core standard-library runtime, verified TLS/DNS pinning, bounded jobs and direct existing-asset findings. Preserve three-valued applicability, aliases, raw-record/envelope digests, timestamps, source terms, inventory references, and scanner-reported/inferred validation levels. Main assessment schema stays 2; the separately owned public cache has schema 1. No automatic exploitation, target contact, corpus bundling or source-free composite score is introduced.

Use a six-destination primary workspace with a target table/inspector, searchable native tool directory, prepared-context handoffs, and progressively disclosed authentication. Existing advanced tools remain available. Preparation clears prior context/authorization and requires deliberate collection. Nmap adapter 3 retains CPE children; legacy and new derivations remain separate.

## Alternatives and consequences

A single CVE database misses package-specific advisory aliases and prioritization context. A third-party scanner bridge or executable public template feed expands dependencies, trust and execution scope. Bulk mirroring every public corpus creates freshness, licensing and storage obligations beyond this increment. Atlas instead implements bounded native correlation with source-specific responsibilities and explicit partial coverage.

The shared local cache simplifies repeated scans but retains software query identities and uploaded filenames; the data folder must be protected. Cached/offline publisher authenticity is an operator assertion. Applicability remains a conservative subset: opaque ordering/environment gaps need review, and absence of a match is not a clean verdict. In this host's live check NVD failed certificate verification; OSV, KEV and EPSS worked. The product preserves that failure without disabling TLS.

Synthetic tests and real-browser workflows prove the implemented contracts, not target exploit impact or universal database/scanner coverage. UI references guide organization without copying vendor assets. [Vulnerability scans](../vulnerability-scans.md), [operator workflow](../operator-workflow.md) and [verification](../verification.md) record exact scope and acceptance.
