# Desktop verification — 0.9.0

This file records executed release checks. The desktop and companion use synthetic fixtures; prior real HTB data remains outside the source repository. Final counts and platform results are recorded after the release checks finish.

Acceptance requires: actual owned loopback lifecycle and restart persistence; data-directory exclusion; no target collection on startup/import/connect/update; explicit software sharing and inferred evidence handoff; verified TLS/authentication/nonce guards; manual fixed-repository update links; packaged assets/demo operation from an isolated wheel; native renderer launch/navigation/download checks where that platform is available. Tests on one platform do not qualify another platform's native GUI or VPN.

The previous HTB test established that a different operator host had the target VPN route while the server did not. That test does not establish desktop installation or target execution from this release. No extra HTB target activity is initiated by this packaging change.
