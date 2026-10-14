# Security and assessment boundaries

Version 0.3.0 is a single-operator application bound only to `127.0.0.1`. It uses a per-process session cookie, same-origin mutation checks, an in-memory request nonce, restricted static paths, and no import-initiated network or command execution. It is not a remote/multi-user service or an independently audited security product. Review the [actual verification and limitations](docs/verification.md).

Authenticated scans keep credentials, login tokens and cookie snapshots in bounded process memory; login bodies are always metadata. Exact-origin cookie jars and repeated protected-session checks limit leakage and stop lost-session audits. Custom checks and OpenAPI inventory are inert data; no uploaded code executes. See [authenticated scanning](docs/authenticated-scans.md).

SQLite holds normalized, best-effort sanitized excerpts and assessment records; original input bytes are not stored. The OS account and disk protection provide at-rest access control; there is no application encryption, user account system or guaranteed forensic erase. Back up/restore only while the app is stopped. A process lock prevents concurrent app instances from opening the same data directory. Default exports withhold identifiers and free text; including them requires an explicit checkbox. Inspect all sensitive exports because pattern-based secret detection cannot find every secret. Original files, external backups and downloaded exports remain outside application deletion.

## Authorized engagements

Before live collection or testing, record the engagement authority, approved targets and exclusions, permitted methods, time window, testing vantage points, operator, stop conditions, sensitive-data handling, and cleanup obligations. Existing authorization can cover bounded actions within that scope; request a new decision when targets, methods, impact, or distribution exceed it. Importing an artifact is not authorization to contact its hosts.

Offline import must work without contacting discovered addresses. Native web tools are now implemented with the boundaries in [Web security](docs/web-security.md) and [setup/retention](docs/web-tools.md). Full scanner/protocol/SPA coverage remains unqualified. Live collectors must be deliberately enabled with an inspectable plan of commands or API requests, least-privilege access, target checks, resource limits, timeouts, cancellation, and an activity record. Importing configuration, obtaining router access, or drawing a graph must never trigger collection automatically. Default to read-only management behavior; device modification needs separate explicit authority.

## Untrusted imports

Treat scan results, configurations, logs, filenames, banners, and embedded text as data. Never execute or obey them. Current XML intake rejects external/custom DTDs and entity declarations; it strips Nmap's inert default declaration and stylesheet processing instructions without executing or fetching them. Inputs are bounded to 8 MiB with nesting/item limits. Rendering uses text nodes and escaped HTML. There is no archive support or arbitrary file-serving endpoint. Imported URLs are not fetch instructions. Evidence references cannot read source files through the app.

Adapters run under bounded permissions. Errors must not corrupt an existing engagement or convert unsupported input into confident topology. Validate trust boundaries with synthetic hostile inputs before claiming an adapter is supported. The first import workflow must demonstrate no network activity caused by import.

## Sensitive evidence and secrets

Real device configurations and assessment outputs may expose passwords, keys, tokens, community strings, internal addresses, personal information, and exploitable access paths. Keep them outside this source repository, issues, CI logs, and routine screenshots, even while the repository is private. Use entirely synthetic fixtures here.

For future workspaces, choose an owner-approved storage, access-control, retention, backup, and deletion policy before handling real evidence. Retain raw evidence references and integrity digests, with raw bytes held in controlled storage; redact derived displays and exports by default. Keep credentials separate from the evidence model using an appropriate secret mechanism. Never retain secrets just to make an observation reproducible. Where source time or vantage is missing, record the gap rather than fill it with import time.

Deletion must cover raw artifacts, derived observations, exports, temporary files, backups under their retention policy, and collector credentials or agents. Preserve only an authorized minimal audit/tombstone record. Evidence immutability means changes are traceable while retained, not that sensitive material can never be removed. Export must require an explicit destination and content selection, preserve limitations, and allow preview/redaction. Do not send evidence to remote analysis services without authorization.

## Reporting a vulnerability or exposure

Contact Brayden privately using an established channel. A dedicated security mailbox and GitHub private vulnerability reporting have not been configured or verified. Do not open a public issue containing sensitive details. If no private channel is available, request one without including exploit details or evidence.

Provide the affected commit or future version, impact, prerequisites, and a minimal synthetic reproduction. Exclude credentials and client artifacts. The owner triages, records severity and scope, coordinates a fix and retest, and agrees disclosure with the reporter. No response-time SLA is promised at this stage.

If a secret or real engagement artifact is committed, stop further propagation, notify the owner privately, revoke or rotate exposed credentials, assess affected access and copies, and arrange appropriate history cleanup and deletion. Removing the latest file alone does not remove history or downloaded copies. Record the containment and verification outcome without reproducing the secret.

Related: [Governance](GOVERNANCE.md), [evidence lifecycle](docs/architecture.md), [delivery gates](docs/roadmap.md).
