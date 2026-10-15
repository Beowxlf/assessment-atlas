# Dependable execution context

Version 0.8.0 connects an investigation's intended execution host and route policy to a fresh, measured preflight. The browser accessing Atlas does not supply the server's network route. No outbound Kali/Parrot connector is introduced.

## Prepare, check, run

1. In **Investigations**, review the reported Atlas execution host and save the expected interface with the question. For an HTB VPN running on Ubuntu, select the interface that the approved VPN actually created. Do not assume its name. An explicit **system** policy permits ordinary host routing and supplies no VPN assurance.
2. Prepare the test, review the exact target, scope, protocol, limits and intended identity. Preparation clears prior credentials and authority. For authenticated work, establish a transient session with a protected guard. Account role/reference labels express operator intent; a successful guard proves a checked session, not the application's authorization policy.
3. Confirm authority and select **Check execution context**. This resolves scoped names and inspects the server's routes; it does not connect to the target application. Review the host, selected interface, source addresses and limitations. A missing, down or mismatched interface blocks the test. On platforms without Linux route checks, only the explicit system policy is available.
4. Start the bounded test within the short review window. The check is single use and belongs to that workspace, operator, scope, investigation revision and transient session/configuration. Changing test details requires another check. Starting another run also requires a new check.
5. Inspect the linked run and its evidence. Atlas retains measured host/route context separately from the saved expectation. Unknown historical context stays unknown. A route change, session loss, cancellation or restart preserves incomplete execution and completed observations; it does not establish a clean negative result.

An installation-specific opaque host ID is retained beside the protected database. Preserve it with backups when restoring the same execution installation. Moving an assessment to another installation requires reviewing and saving the new host expectation. Host IDs identify an Atlas installation; they are not hardware attestation or protection against a privileged operator modifying its files.

## Safe continuation

An incomplete linked web test offers **Prepare again**. Atlas checks the current investigation revision and original run ownership, then prepares a new test. It retains the original run, its outcome and evidence. The subsequent run records the original run ID so the sequence can be reconstructed.

A sanitized URL, original main-origin path boundary/exclusions and bounded numeric limits are offered as conveniences. Additional origins are omitted, keeping the prepared scope within the original boundary. Query strings, headers, request bodies, payloads, authentication, preview tokens and authority are not restored. Review the exact URL, scope and test settings; enter required inputs again. This is a fresh bounded test, not a cursor-based continuation or automatic replay. State-changing requests require explicit reconstruction and review. Active/completed runs cannot be resumed through this action; shell input, proxies and socket messages require manual preparation from their evidence.

Browser reload or service restart does not restore execution authority. Queued/running persisted tests become interrupted. Resume preparation itself neither mutates the original run nor sends a target request. Re-establish authentication and repeat the current host/route check before starting.

## Enforcement and limits

Native web transport shares the context guard across supported protocols, with scoped DNS pinning, source/interface binding and repeated route checks. Standalone proxy/WebSocket context review uses the same guard. Investigation-linked collection currently supports request/crawl/scanner/payload/matrix runs; proxy/socket and embedded-browser handoffs require separate manual preparation and never silently discard a bound investigation.

Configured terminal operations require a fresh single-use host/route review bound to the operator, workspace and exact plan; a changed route/source between preview and launch is refused. They retain their exact target/profile, bounded output, lease and route/source checks every five seconds. The curl HEAD profile explicitly binds its interface. Nmap receives the measured local source/interface and remains a sampled route check with no strict device-binding guarantee; do not treat it as equivalent native socket enforcement. The interactive shell remains trusted operator access and cannot guarantee that manually entered commands obey an investigation's scope; it is labelled accordingly. The [Nmap options](https://nmap.org/book/man-bypass-firewalls-ids.html) and [curl interface contract](https://curl.se/libcurl/c/CURLOPT_INTERFACE.html) are primary references; installed behavior is separately qualified in the release receipt.

An interface and route observation does not identify an HTB VPN profile, prove the remote lab is the intended one, or establish target authorization. No real HTB profile or target was supplied for this release. Owned loopback fixtures and controlled route-change cases qualify the implemented mechanics separately from a future HTB trial. Routes can change during an in-flight exchange; stopped/partial coverage is retained rather than retroactively recast as a complete test.

Older standalone tool clients remain compatible when no execution policy is selected. Explicitly context-bound tests and investigation-linked tests require current review. Public vulnerability-database queries contact fixed public advisory services rather than assessment targets; offline imports remain inert and do not need a target VPN route.

## Persistence and reporting

The additive investigation field is `execution_context: {host_id, interface}` or absent/null for legacy records. Measured run context uses a server-derived allowlist: host identity/name/platform, interface/policy, checked time and route target/interface/source/gateway. Tokens, owner sessions, credentials and request configurations remain transient. Default exports withhold this context and interruption free text; included exports retain it deliberately. SQLite schema 2 and investigation schema 1 remain unchanged.

See [ADR 0009](adr/0009-dependable-execution-context.md), [investigations](investigations.md), [authenticated scans](authenticated-scans.md) and [verification](verification.md). The exact release receipt identifies executed checks and environments.
