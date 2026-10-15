# NorthGate live validation — 0.1.1

Validation date: October 12, 2026 (America/Chicago). This report is sanitized. Real input files, endpoint identifiers, addresses, detailed maintenance receipts and the live test database remain in a protected private evidence directory outside this Git repository. No live screenshots, certificates, keys, tokens, configurations or engagement artifacts are bundled.

## Secure lab connection restored

The prior expired-certificate blocker was repaired through the existing independently pinned, key-only administrative SSH route. The actual operator leaf and its existing internal server/workload maintenance set had expired; their original CA roots remained valid. Twelve leaf certificates were renewed using the existing offline issuers, preserving CA and leaf keys, subjects, extensions, identity bindings and the established 30-day renewal lifetime. Client-certificate fingerprint allowlists and signed certificate status were refreshed to match the renewed certificates.

Protected backups preserve the exact 30 replaced public-certificate/configuration files. Their hashes/readability and all 12 affected private-key hashes were verified. Initial refresh attempts encountered shutdown deadlines and OIDC discovery against the still-expired front-door certificate; files were rolled back, and the maintenance/audit timers were restored before the corrected recovery. The final procedure accounted for configured stop deadlines, loaded signed status and nginx TLS first, then verified IdP discovery before starting dependent services. It completed in 28.86 seconds; this is the final refresh duration, **not total downtime**, which was not measured across the earlier interruptions.

The final suite verified 12 valid leaves, 11 active services, both certificate-status/audit-export timers enabled and running, IdP discovery returning 200 through verified HTTPS, and unauthenticated native RPC returning 401. Operator/IdP peer certificates passed hostname and unchanged-CA checks over TLS 1.3. The actual connector returned authenticated service-key grants and job contracts. No host/VM reboot, firewall/network change, new exposure, CA replacement, secret export or authentication weakening occurred. Temporary public-only staging was removed; protected backups were retained. Human owner login/MFA was not repeated.

Leaf validity ends November 12, 2026 at 00:18:09 UTC (November 11 at 6:18:09 p.m. America/Chicago). Renewal remains the existing manual maintenance process; this work adds no recurring automation or endpoint-agent replacement.

## Actual product workflow

Inputs and testing positions:

- **Nmap 7.95 XML:** actual connect scan from an existing verified Parrot lab VM, confined to one owned control-plane target and two TCP ports. No version/OS scan, NSE scripts, traceroute, vulnerability tests or broader subnet sweep was performed.
- **Linux iproute2 6.1.0:** two actual read-only address/route/neighbor snapshots from a verified Linux control-plane guest via pinned SSH. The first snapshot contained six interfaces, 26 route records and six neighbors. Collection time and testing position were supplied/preserved.
- **Common manual JSON:** corroborated live Hyper-V adapter/guest identity, Linux interface MAC, pinned SSH hostname, and a live authenticated RMM management-state response, normalized into two sourced observations. It is manual evidence intake, not another scanner run.

Four direct browser imports yielded **94 source entities, 118 observations and 96 typed relationships**. The real workflow checked map inspection, keyboard evidence drilldown with provenance/hash/time/vantage, a corroborated identity link and undo without losing source observation IDs, an assessment test record, repeated-file deduplication, two retained snapshots, redacted JSON/HTML/SVG downloads, and persistence through browser reload **and actual application-server restart**. No page errors or non-loopback browser requests were observed. Atlas imports caused no scans or outbound fetches.

Identity reconciliation used independent VM/MAC/pinned-SSH corroboration; a shared IP alone was not proof. Operational route/neighbor evidence remained distinct from physical wiring, VLAN claims, configured intent, and tested transport reachability. No independently validated vulnerability or compromise was established.

## Fault found and corrected

The actual Nmap XML reported host `up` with reason `user-set`, one filtered TCP port and one open TCP port. Atlas 0.1.0 had labeled that host status observed. Version 0.1.1 now retains the original scanner values but labels scanner-forced host status **unknown reachability / configured assumption**, while preserving actual port states and their independent active-test basis. Filtered remains filtered; it is not closed or proof of a specific firewall rule.

New tests cover a forced-up host with an open port, missing host-discovery status, and a forced-up host with **only filtered/no responding ports**. The latter cannot become confirmed reachable solely from the scanner tag. This follows [Nmap's documented skipped-discovery behavior](https://nmap.org/book/host-discovery-controls.html).

Adapter revision is now 2. Existing saved observations are not silently rewritten; re-importing after the upgrade creates a distinct versioned derivation while retaining prior history. A persisted adapter-1 upgrade test verifies that identical-file deduplication permits the adapter-2 reimport, preserves earlier observation IDs, records and history, and deduplicates subsequent adapter-2 repeats. Use the original file and same import context to append the corrected derivation; review historical host claims against its new evidence. Database schema remains 1. The current full automated suite passes **35 tests**; final package validation is tied to the revision in its manifest/receipt.

## Exact limits

Nessus, Nuclei and httpx remain verified by synthetic fixtures only. No live credentials/results/runs for them were invented. Traceroute, OS fingerprints and vulnerability impacts were not exercised in the bounded live scan. Live Atlas ran locally using lab evidence; no Atlas deployment to a lab VM is claimed.

The RMM control-plane endpoint's agent/worker remained reported offline/unready, with stale heartbeat data, despite the guest being reachable through verified SSH and the scoped scan. These are different vantage/evidence levels; agent-backed collection and broader fleet recovery remain unverified. The live workflow used the existing secure SSH route, not queued jobs to an offline worker. No agents or credentials on endpoints were altered.

The [general release limits](verification.md) still apply: single local operator, no application encryption, bounded formats/display, best-effort scrubbing, no universal vendor/version matrix, no remote collaboration or independent audit, and licensing still pending. The product PR remains reviewable; local/live verification does not itself imply a public release or owner acceptance.
