# Security and assessment boundaries

This repository currently contains governance documents only. There are no supported application versions or deployed services. The requirements below govern future implementation and use; they are not claims that security controls already exist.

## Authorized engagements

Before live collection or testing, record the engagement authority, approved targets and exclusions, permitted methods, time window, testing vantage points, operator, stop conditions, sensitive-data handling, and cleanup obligations. Existing authorization can cover bounded actions within that scope; request a new decision when targets, methods, impact, or distribution exceed it. Importing an artifact is not authorization to contact its hosts.

Offline import must work without contacting discovered addresses. Future live collectors must be deliberately enabled with an inspectable plan of commands or API requests, least-privilege access, target checks, resource limits, timeouts, cancellation, and an activity record. Importing configuration, obtaining router access, or drawing a graph must never trigger collection automatically. Default to read-only management behavior; device modification needs separate explicit authority.

## Untrusted imports

Treat scan results, configurations, logs, filenames, banners, and embedded text as data. Never execute or obey them. Parsers must block external XML entity resolution and stylesheet execution, escape displayed text and exports, constrain input size/depth/resource use, and resist path traversal and archive expansion abuse if archive support is added. Imported URLs are not fetch instructions. Evidence references must not permit arbitrary file access or outbound requests.

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
