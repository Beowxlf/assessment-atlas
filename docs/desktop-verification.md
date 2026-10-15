Current native Parrot acceptance is in [suite verification 0.10.0](suite-verification.md). The results below preserve the earlier 0.9.0 state; its Linux GUI gap has since been closed for the tested system-Qt/offline profile.

# Desktop verification — 0.9.0

The desktop and companion use synthetic fixtures; prior real HTB data remains outside the source repository. Code qualification used `4faf8a81210a13434ffb5bc761f8bc4eee5c986d`; later release documentation does not change those runtime bytes.

| Executed check | Result and practical limit |
| --- | --- |
| Windows Python 3.12, full protocol/TLS dependencies | 206 tests run: 199 passed, 7 Linux/POSIX skips, 163.8 seconds. Includes authenticated testing, vulnerability correlation, execution review and shutdown final-writer checks. |
| Exact extracted package on Ubuntu, unprivileged account | 206 tests passed, no skips, 166.2 seconds. The existing service and its assessments were not used by these disposable fixtures. |
| Actual Microsoft Edge workflows | All 11 scripts passed: imports/map/evidence/reconciliation/exports; native/authenticated web tests; protocols/WebSockets/callbacks; vulnerabilities; operator console and conveniences; investigations; execution context; desktop companion UI. Two analysis responses and an update failure were stubbed only for UI race/error cases, without retaining mock evidence. |
| Actual Windows WebView2 native window | UI rendered, real renderer session/nonce saved an assessment/investigation, external navigation was cancelled, file navigation stayed blocked, and local data/host identity survived close and reopen. |
| Actual verified-HTTPS companion fixture | Login/capability negotiation, software-only upload, cache matching, explicit inferred-evidence save and default export withholding passed. No confirmed finding or target request was created. |
| Wheel/source/install checks | Wheel and source archive rebuilt with identical runtime bytes; fresh offline wheel installation served assets and all six demo imports. Windows per-user installer installed the optional engines. |
| Public GitHub package jobs | Both Ubuntu 24.04 and Windows jobs passed regression, source/wheel rebuild, isolated wheel installation and artifact upload at the qualified code revision. [Run](https://github.com/Beowxlf/assessment-atlas/actions/runs/38735396598). |
| Existing private companion deployment | Upgraded the existing private server to the qualified 0.9.0 runtime, backed up its SQLite database and verified every previous assessment field/ID and operator-auth file remained unchanged. Actual verified-HTTPS sign-in and synthetic software-only analysis succeeded. Its advisory cache was empty: no live cache match or target finding is claimed. |

The public-history review covered the previous 23 reachable commits, 386 unique blobs, 133 tracked files and existing PR discussions. No live credentials or engagement artifacts were detected; xterm files matched their recorded provenance and retained their MIT notice. This pattern/manual review is not a guarantee against disguised secrets. New runtime/package material contains only code and synthetic fixtures. The owner selected public source with all rights reserved.

Review found and corrected the Qt 6 download API incompatibility, stale companion asset choices after import, stale response/consent handling, and a shutdown race. Storage remains locked until admitted requests and cancelled final evidence writers finish; manager draining avoids resource-thread self-join cycles.

Linux native GUI acceptance remains **unverified**. On the existing Parrot host, the exact public source was downloaded over verified HTTPS and all 55 Atlas files matched the qualified source digest. Its isolated Qt dependency preparation reached the bounded 110-second automation limit before renderer acceptance. No RDP session, system package, route, VPN or trust setting was changed, and no installation retry or background job was started. This is an environment/time-bound acceptance gap, not a verified renderer failure. The Linux installer is provided; Python/runtime/route/terminal workflows are separately qualified by the full Ubuntu suite. A real Parrot desktop launch and native report download remain required before claiming that GUI qualified.

Acceptance requires: actual owned loopback lifecycle and restart persistence; data-directory exclusion; no target collection on startup/import/connect/update; explicit software sharing and inferred evidence handoff; verified TLS/authentication/nonce guards; manual fixed-repository update links; packaged assets/demo operation from an isolated wheel; native renderer launch/navigation/download checks where that platform is available. Tests on one platform do not qualify another platform's native GUI or VPN.

The previous HTB test established that a different operator host had the target VPN route while the server did not. That test does not establish desktop installation or target execution from this release. No extra HTB target activity is initiated by this packaging change.
