# ADR 0009: Dependable execution context and reviewed continuation

**Status:** Accepted within the owner's explicit implementation request, October 15, 2026.

## Context

The owner requested the next roadmap step: correct execution host, VPN route and authenticated session, with safe resumption and all checks. Investigations already persist reasoning and link native runs, but free-text vantage labels cannot establish the execution host. Configured terminal operations inspect an interface; native web collectors need a consistent measured policy. Restoring an entire test would also restore sensitive inputs and stale authority.

## Decision

Keep the existing Ubuntu execution host and add an opaque installation identity, explicit investigation host/interface expectations, and transient single-use preflight checks. Bind review to workspace/operator, target/scope/configuration, investigation revision and current authentication context. Inspect scoped routes, require an explicit system policy where interface enforcement is unavailable, recheck during execution and bind supported transports to the measured source/interface. Retain only allowlisted measured proof in run snapshots. Fail clearly on unavailable context rather than silently switching hosts or routes.

Keep authentication ephemeral, scope-bound and checked through protected-session controls. Intended role/account references remain metadata. Clear session authority across sign-out/restart. No saved reference substitutes for a usable session or demonstrated authorization.

Prepare an incomplete linked web test through a nonmutating endpoint. Offer only sanitized URL/numeric limits, require reconstruction/review of request specifics, and start a new run linked to its predecessor. Never restart collection automatically or alter the original incomplete outcome/evidence. Active/completed jobs and arbitrary shell/socket replay are excluded.

Keep SQLite schema 2 and investigation envelope version 1; add nullable expectation and allowlisted snapshot fields. Preserve old records and IDs, redact new context by default, and keep preview capabilities out of saved data and exports.

## Alternatives and consequences

Free-text labels and a one-time route check are inexpensive but permit silent context drift. Persisting full workbench state would improve convenience at the cost of secrets and stale authority. An outbound execution agent would add another trust boundary without resolving the existing host's consistency. The selected change completes the current execution path while leaving a future Kali/Parrot connector independent.

An installation ID is not hardware identity. Source/device binding and repeated route observations constrain the selected path; they cannot prove a particular VPN provider/profile or eliminate all in-flight changes. The trusted interactive shell remains manual operator access. Legacy standalone clients without an explicit context policy stay compatible. Existing assessments with unknown historical context are not backfilled with invented measurements.

## Verification

Require host/route mismatch, down/changed interface, source change, token expiry/reuse, cross-workspace/operator, scope/configuration change, expired/forgotten authentication, interrupted preparation, new-run lineage, default redaction and restart checks. Run existing import, scanner, protocol, console and investigation regressions. Qualify actual Linux interface mechanics and private-service restart separately from synthetic route faults. A real HTB VPN/target and a human productivity trial remain unverified until independently supplied and exercised. See [execution guide](../execution-context.md) and [verification](../verification.md).
