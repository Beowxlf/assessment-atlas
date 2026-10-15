# 0010 — Operator-host desktop with an optional computation companion

Status: Accepted within the owner's October 15, 2026 request to replace the hosted-first workflow with a standalone app using the operator host's VPN. The owner explicitly authorized making the repository public and selected public source with all rights reserved.

## Problem and choice

The hosted browser UI executes tools on the server. An RDP user's lab VPN on another machine is unavailable to those collectors. A browser extension cannot supply a remote server with that host's routing table or local PTY. An outbound execution agent would add enrollment, job authority, secret transfer, liveness, routing and recovery protocols before resolving the immediate lab workflow.

Retain the existing evidence/workflow model and Python implementation, run it on the operator host, and show the existing interface in a native pywebview window. The runtime binds an OS-assigned loopback port and owns its cleanup and existing data-directory lock. Linux Qt/PySide6 and Windows WebView2 are the qualified renderer paths; a regular local browser is an explicit fallback. This is a native shell with local collectors, not a rewrite into native widgets or a bundled VPN. Python and platform prerequisites remain required.

## Boundaries and consequences

- The operator installs on the VPN host. Local execution review measures that installation and route. Existing Linux terminal/route enforcement remains Linux-only; no Windows feature parity is invented.
- Local SQLite and evidence custody remain authoritative. Existing server assessments remain on that server until a future reviewed migration/synchronization workflow is implemented.
- The window exposes no application Python API and cannot navigate to targets, arbitrary remote content or local files. Existing scoped browser tooling handles target interaction. Transient sessions and single-use execution reviews are unchanged.
- The companion is optional, explicit, verified HTTPS. Its first computation contract accepts only reviewed public software identities for bounded cache-only advisory matching. It accepts no target execution jobs. The local client can retain inferred results and prepare a manual finding with its evidence reference.
- Stable release checks use a fixed GitHub endpoint on explicit user action. Updating is a reviewed manual installation, with separate data-folder preservation. No arbitrary downloaded code or automatic downgrade/migration runs at startup.
- Source and wheel packaging includes only code/assets and synthetic fixtures. Public visibility is not an open-source license grant; third-party notices remain intact. A public GitHub repository need not contain engagement evidence to distribute an installer.

Revisit when signed native installers, multi-user synchronization, offline advisory indexes larger than the current bounded cache, additional desktop platforms, or a justified remote execution use case needs acceptance. Do not reintroduce remote target execution as an implicit fallback when the local VPN is lost.

Verification is recorded in [desktop verification](../desktop-verification.md); unexecuted platform scenarios remain limitations.
