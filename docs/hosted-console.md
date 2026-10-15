# Hosted operator console

Version 0.6 adds an opt-in, single-operator Linux deployment, embedded terminal, interactive scoped browser and evidence-to-finding handoff. The terminal and target browser run **on the Atlas execution server**. A VPN on the operator's browser machine supplies no route to that server. The outbound Parrot/Kali host connector remains unfinished; no local browser extension is required for the implemented remote browser.

## Operator workflow

1. Sign in through the deployment's fixed HTTPS address and select an assessment. Open **Tools → Embedded terminal** or use the tool finder.
2. Connect the authorized HTB VPN on the execution host through its administration workflow. Select the expected interface, one exact IPv4 target, profile and limits. Preview the actual route and plan, then explicitly authorize it. Imported targets never execute automatically.
3. Run common/all TCP discovery, light service enumeration on selected ports, or an HTTP HEAD inspection. Nmap/curl output feeds the same assessment, map, observations and evidence provenance. Review identities before merging; matching addresses do not merge automatically. A timeout, route failure or incomplete Nmap result cannot establish a clean verdict.
4. For manual operations, open the interactive terminal. It has the app account's privileges and operator-controlled scope. Input/output buffers are transient; explicitly select a short excerpt for documentation.
5. Open **Embedded browser**, specify the permitted origin/path scope and any public target CA, then authorize navigation. Click, type, scroll and read visible text inside Atlas. Pages are rendered in an isolated server browser, allowing targets that reject iframe embedding. JavaScript navigation and subrequests still pass through the scoped, TLS-verifying proxy.
6. Use **Prepare authenticated audit** after signing in. Set a protected check URL and signed-in marker, explicitly obtain the browser cookies and authorize the audit. Preparing controls starts no scan and carries no previous scan authority or credential selection.
7. Review an excerpt, choose an existing assessment identity and select **Save evidence and draft finding**. The draft includes an evidence reference; save the interpretation and independently demonstrated impact. Manual findings appear in Findings and reports. Native run/page references accompany selections when available; editing an excerpt remains manual evidence.

The browser screenshot stream and credentials are transient. The raw configured-operation files are separately retained in the protected `data/terminal-evidence` directory; exports contain normalized observations and digests, not those files. Confirmed assessment deletion removes its owned originals after active operations are stopped; independent copies and backups require separate custody. Default exports withhold identifiers and free text. Scrubbing is best effort: review cookies, passwords, VPN keys and unrelated data before retaining or sharing excerpts.

## Ubuntu deployment contract

Keep the Python backend on `127.0.0.1`. Provide a fixed HTTPS reverse proxy that overwrites Host and X-Forwarded-Proto, and start with `--public-url https://192.0.2.50`. Set the public URL to the actual fixed server address; do not forward untrusted client identity headers. Bind the HTTPS listener to the intended private management interface, keeping it off a lab VPN interface. Atlas refuses direct non-loopback backend binding and unexpected public Host/protocol/Origin values.

Run the service as a normal account. Python 3.12+, Node, Playwright Chromium and its Ubuntu browser dependencies are required. Nmap, curl and iproute2 supply the typed profiles. OpenVPN is administered separately; Atlas does not ingest VPN credentials or elevate to root. Linux browser sessions require the Chromium sandbox; no privileged container or `--no-sandbox` fallback is implemented.

The [runtime installer](../tools/install_hosted_runtime.py) installs Python and the pinned Node/Playwright runtimes under a pre-provisioned writable service directory, using official verified HTTPS downloads and recording a receipt. Ubuntu 22.04's system Python can run that installer, but cannot run the app itself. Install the browser OS packages as an administrator; [Playwright's browser documentation](https://playwright.dev/docs/browsers) describes those dependencies. Python comes from Astral's managed distributions, as described in [uv's Python installation guide](https://docs.astral.sh/uv/guides/install-python/). The installer refuses an existing completed runtime instead of silently upgrading it.

Create the operator password with `python -m atlas.hosted_auth --data-dir /protected/atlas-data`; the hidden prompt keeps it out of shell arguments and logs. Only a salted password hash is persisted. Serve through HTTPS with a trusted certificate, or a deliberately pinned lab certificate. Installing a certificate into global client trust is an owner administration step. Start the service with ATLAS_NODE, ATLAS_PLAYWRIGHT_MODULE, PLAYWRIGHT_BROWSERS_PATH and ATLAS_BROWSER_CHANNEL=chromium pointing to the installed runtimes. A fresh install must create and protect its data directory before accepting assessments.

Sessions use secure HttpOnly SameSite cookies, separate nonces and an eight-hour lifetime; logout and server restart invalidate them. Wrong password attempts are limited. Terminals and browser control are bound to the assessment and browser session. This remains one trusted operator account: all signed-in clients share assessment storage. A shell can access app-account files and connect to operator-selected hosts; this is not a multi-tenant execution sandbox.

## Limits and qualification

Terminals are Linux-only and refuse root. Two active terminals, 30-minute shell lifetime, 35-second browser connection lease, 524,288-byte display buffer and bounded inputs apply. Configured profiles accept 15–600-second execution, one exact IPv4 target, at most 1,000 explicitly selected ports, an 8 MiB output bound and repeated expected-interface route checks. Their immutable preview digest and request ID prevent accidental changes/duplicate launches. Configured operation input allows cancellation only. Nmap connect scanning does not implement UDP, privileged SYN scanning or NSE execution. Nmap packet/request counts remain unavailable.

The embedded browser has a 1280×800 viewport, bounded screenshots/actions, serialized input and a connection lease. Clipboard paste uses the explicit input control. Browser-local storage token transfer, multi-role authorization matrices, browser extensions, remote host connectors and full competitor/scanner parity remain gaps. HTB VPN routing and a real HTB target require separate live acceptance with the supplied profile and target; fixture success proves neither.

See the [operator workflow](operator-workflow.md), [native web coverage](native-web-coverage.md) and [vulnerability scans](vulnerability-scans.md). Public advisory findings remain applicability leads until patch/configuration and actual impact are validated. Inventory coverage now reports how many candidates are omitted by the first-100 display limit; use reviewed explicit/SBOM selections for further software.

## Operator conveniences — 0.6.1

Discovery prepares exact address/known-port or URL drafts for the console, without execution or authorization. Browser setup collapses after start, locks the active scope and provides explicit guarded page navigation. Authentication preparation retains the reviewed path prefix. Assessment drafts remain in tab memory by workspace; a new evidence handoff cannot overwrite an unfinished draft. See [Operator conveniences](operator-qol.md).
