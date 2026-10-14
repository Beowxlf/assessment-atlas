# 0005 — Protocol engines and owned interactions

Status: Accepted within explicitly authorized implementation scope, October 14, 2026. Basis: Brayden requested remaining native Burp-style capabilities including WebSockets, HTTP/2/3, out-of-band testing and broader scanner coverage, with findings entering the assessment directly. This records reversible local engineering choices; it grants no new external assessment, public hosting, distribution or licensing authority.

## Decision and evidence

Keep the existing exact-origin/path scope and numeric address pins for every transport. Use optional pinned sans-I/O engines (h2, aioquic and wsproto) with verified original-hostname TLS. HTTP/3 uses a connected UDP socket, rejects address migration and performs no Alt-Svc, 0-RTT or silent fallback. The browser/proxy downstream remains HTTP/1.1; upstream protocol selection is separate. Bounded real TLS/QUIC fixture exchanges and negative CA cases validate the executed subset.

Use classic RFC6455 WebSocket channels and the scoped isolated-browser proxy for complete text/binary messages, capture/edit/replay and both-direction interception. Preserve the received original before a manual edit, including correlation/digest, and discard raw buffers on close. Reuse workspace-owned transient authentication for an independently guarded handshake; budget login/guard/handshake/message operations and save failures. Browser authorization for WebSocket paths is checked before the connection.

Use an owner-controlled HTTP/DNS receiver with short-lived unpredictable tokens and explicit local interface/exposure controls. Keep default loopback; make no automated firewall/NAT/DNS/public-hosting changes. Do not use a third-party public Collaborator service. Record actual token receipts as source-reported findings and preserve peer/time/protocol, issued/probe/baseline correlation. Matching token receipt proves a receiver event, not target causality, SSRF/RCE or data disclosure. Callback bodies/tokens are not retained as raw evidence.

Add original controlled SQL/NoSQL/LDAP/XPath/command-shaped/XML, explicit file/CSRF/cache canary, redirect and callback checks. Put every probe/control through the existing session guard, rate/request/time/cancellation gate. Require explicit isolated stateful/file canaries; use reserved domains for tests that must not be followed. Never upgrade a scanner assertion into validated impact through review status alone.

Normalize all outcomes through the existing assessment, immutable evidence, Findings, review/report model. Web adapter revision 4 is additive; database schema stays 2 and existing imported evidence is preserved. Other adapters stay revision 2. Imported source labels, transport/authentication and callback assertions are inert source data, not independent proof or execution authority.

## Alternatives and consequences

Using a high-level HTTP client with fresh DNS resolution or hidden protocol fallback would weaken current scope pins; use explicit engines and one-request bounds. A public callback service would introduce privacy, hosting and delegation decisions; use the bounded owner-configured receiver. Copying a browser profile would broaden credential exposure; continue fresh contexts and explicit scoped sessions. Arbitrary uploaded checks would require code isolation and a new permission contract; checks remain original native code or literal declarative predicates.

Optional dependency installation and a representative interoperability/accuracy corpus are still required beyond this fixture qualification. HTTP/2 extended CONNECT, WebTransport, full binary/streaming HTTP editing, broad advanced scanners, automatic CSRF rollback/cache invalidation and secure memory/forensic erase remain unsupported. Current limits, setup, synthetic fixture behavior and remaining gaps are in [the workflow](../protocols-and-callbacks.md) and [coverage matrix](../native-web-coverage.md); exact extracted-package evidence belongs in its versioned receipt.
