# 0007 — Hosted operator console

Status: Accepted within the owner's requested implementation and Ubuntu hosting scope, October 14, 2026.

The owner requested browser access to a Linux-hosted HTB assessment workspace, an embedded terminal/browser and a quick transition from enumeration to documented findings. The previously paused outbound host connector is still separate unfinished work. Imported material must remain inert, and reachability must disclose its execution vantage.

Use the existing Python/SQLite model with an opt-in fixed HTTPS reverse proxy and one operator password. Keep the backend on loopback. Add owner-bound, unprivileged Linux PTYs and immutable typed Nmap/curl operation previews; check their actual expected-interface route before and during execution. Preserve normalized results in existing assessment imports and separately protect bounded original operation files. No root shell, arbitrary typed executable, imported-command execution or automatic VPN credential ingestion is added.

Render an isolated, sandboxed Chromium browser through bounded screenshots and native input actions, using the existing scoped upstream-verifying proxy. This supports pages that reject iframe embedding and browser clients on different operating systems. An iframe alone could not cover those cases; an extension would require another client installation/trust boundary. Existing transient cookie handoff prepares a verified authenticated audit without carrying scan authority across contexts.

Operator-selected evidence is attached to a reviewed existing identity and creates a manual finding draft with provenance references. Browser/terminal actions remain bound to the originating browser session and assessment. The account, filesystem and assessment are shared by trusted signed-in clients; multi-tenant isolation is not claimed. New authentication and Linux execution need positive and negative acceptance, plus actual Ubuntu browser-sandbox qualification. HTB target/VPN acceptance is distinct from owned fixtures.

Consequences: vendored MIT-licensed xterm.js replaces the previous dependency-free UI claim. The server needs Python 3.12+, Node, Playwright Chromium and OS browser libraries. A VPN must run on the execution server, or future connector, rather than on the browser client. HTTPS origin/certificate maintenance and protected raw output custody are administrator responsibilities. [Hosted console](../hosted-console.md) specifies implementation limits and remaining gaps.
