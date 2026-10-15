# Security and assessment boundaries

Version 0.4.0 is a single-operator application bound only to `127.0.0.1`. It uses a per-process session cookie, same-origin mutation checks, an in-memory request nonce, restricted static paths, and no import-initiated network or command execution. It is not a remote/multi-user service or an independently audited security product. Review the [actual verification and limitations](docs/verification.md).

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

## Public advisory boundary

Investigation-linked tests additionally require an explicit execution-host/interface expectation and a fresh, single-use context review. Reviews and authenticated sessions are bound in process memory; route/context changes stop collection with incomplete evidence. [Execution context](docs/execution-context.md) distinguishes measured routes, intended identity labels, native socket enforcement and sampled external-tool limits. Restoring saved work never restores credentials or execution authority.

Public vulnerability imports/SBOMs are inert. Public API access is opt-in and limited to fixed verified HTTPS routes with public DNS pinning, no redirects, private-target fields, arbitrary API endpoint/key controls or certificate bypass. Queries disclose selected software/advisory identities; the shared local cache retains them and uploaded filenames. Source authenticity/age, applicability gaps, immutable assessment copies and separate exploitation-probability/severity context are required. See [Vulnerability scans](docs/vulnerability-scans.md). Prepared UI handoffs must reset authorization/secret request context and never trigger live collection.

## Optional hosted Linux execution

[Hosted console](docs/hosted-console.md) specifies a fixed HTTPS origin, loopback backend, salted password hash, session/nonce isolation, logout and throttling. Run unprivileged. The interactive shell is trusted operator access to the app account and filesystem; it is not multi-tenant isolation. Credentials, screen streams and PTY buffers are transient, while bounded configured-operation originals are retained separately under protected data/terminal-evidence. Review sensitive excerpts and original custody; scrubbing cannot guarantee every secret is removed. Browser execution requires the Linux Chromium sandbox and verified upstream TLS. A host VPN route is required; browser-client VPN state is unrelated.

## Resumable investigation boundary

[Investigations](docs/investigations.md) persist selected question/decision metadata and existing evidence/run references with optimistic revisions. Prepared tests are bound to that revision and require execution review; run creation/linkage is atomic before requests. Account labels are opaque metadata. No cookie jars, credentials, login recipes, live buffers or executable plans are restored. Restart retains interrupted results and requires authentication again. Manual finding handoff is explicitly unvalidated. New free text and snapshot context follow default export withholding; selected evidence retains its original capture/retention limits.

## Operator-host desktop and companion — 0.9.0

The desktop shell runs the existing application unprivileged on the operator host, with an OS-assigned loopback port, private native browsing context, no application Python bridge, remote/file navigation denial and explicit report-download destinations. Its local database remains separate from the runtime installation. Existing scope/route/session review remains mandatory; a server connection cannot substitute for a missing local VPN.

Companion sign-in/CA/connection data is process memory only. Verified HTTPS and existing hosted session/Origin/nonce checks protect cache-only matching. An exact field allowlist excludes asset/workspace/target/evidence/credential fields from software uploads. Software/package identities themselves may be sensitive and require an explicit review checkbox. Analysis results are untrusted source reports and may be retained only by explicit local action as inferred evidence. No target operation, automatic source lookup or confirmed finding is produced by the companion.

Stable update checks contact a fixed GitHub endpoint only when requested; verified release links open on explicit action. Updates never execute downloaded code automatically. Source is publicly visible with all rights reserved; publication does not make engagement data suitable for the repository. See [desktop setup](docs/desktop.md).

## Shared suite and retests

Suite apps share the existing assessment and authority boundary; app selection executes no tool or target request. Retest preparation creates/reuses a linked investigation with no session or execution authority. Versioned retest metadata uses strict fields, workspace-local references, idempotent creation and revision checks. Originals remain unchanged; reported outcomes are operator assessments with explicit evidence and completeness limits. Default exports withhold retest free text and copied execution context. The explicit Linux system-Qt install profile requires Qt 6 WebEngine and keeps the Chromium sandbox enabled. See [suite workflow](docs/suite-workflow.md).

Terminal rendering uses a fresh document-local CSP style nonce through a scoped xterm document adapter. It grants no script authority, changes no global document methods, and leaves ordinary inline style/script content blocked. Native startup installs the navigation boundary and finishes the protected blank document before loading an assessment.
