# Desktop Atlas and the host VPN

Version 0.9.0 adds an installable Linux/Windows desktop shell around the existing assessment workspace. Its local Python process owns collection, SQLite persistence and an ephemeral loopback listener; the native window is the interface. Install it **on the machine running the lab VPN**. RDP into that machine is fine: the RDP viewer's network is not the collection vantage.

The desktop runtime never routes target operations through the optional computation server. It does not install a VPN, change routes, trust a target certificate automatically, or restore execution authority after restart. Existing host/interface/session review, target scope, cancellation, interrupted-run and evidence-to-finding rules still apply. The application remains a single trusted operator product.

## Install on Parrot, Kali or Ubuntu

Use a regular desktop user and Python 3.12 or newer, with `venv` available. Obtain the reviewed source release from [Releases](https://github.com/Beowxlf/assessment-atlas/releases), extract it, open a terminal in that directory and run:

```sh
sh packaging/install-linux.sh
```

The installer creates a dedicated per-user Python environment and an **Assessment Atlas** application-menu entry. It installs the pinned native Qt/PySide6 engine, protocol libraries and interception dependency from Python package indexes. A desktop session and the normal Qt platform libraries are required. It creates no system service and does not require sudo. Nmap, curl and iproute2 must be installed separately for their corresponding discovery profiles. The isolated testing browser additionally needs Node/Playwright and a sandboxed Chromium installation; the desktop UI itself is not the browser used to navigate assessed websites.

The default runtime folder is `~/.local/share/assessment-atlas-runtime`; assessments remain separately in `~/.local/share/AssessmentAtlas` (or under an absolute `XDG_DATA_HOME`). Start the app from the application menu. Connect the lab VPN on this host, create an assessment and investigation, select the measured execution host and expected VPN interface, then preview the actual target route before authorizing a bounded operation. Selecting `tun0` is an expectation to verify, not a command to create or select a VPN. Linux core/terminal behavior is tested; the real Parrot native GUI still needs acceptance because its isolated dependency preparation hit the automation time bound. See [verification](desktop-verification.md).

For a deliberately lighter installation, `python3 packaging/install.py --core-only` installs the same local runtime with a regular browser interface. This still uses the installed host's network. This explicit fallback is useful when a native web engine is unavailable; visiting the remote hosted Atlas page does not have that property.

## Install on Windows

Install Python 3.12+ and the Microsoft WebView2 runtime. From the extracted reviewed release:

```powershell
powershell -NoProfile -File packaging/install-windows.ps1
```

The default runtime is `%LOCALAPPDATA%\AssessmentAtlasRuntime`, with a Start Menu shortcut. Data remains in `%LOCALAPPDATA%\AssessmentAtlas`. Windows supports the desktop assessment and web tools, but the embedded PTY and configured discovery profiles remain **Linux-only**. Linux named-interface enforcement cannot be claimed for a Windows VPN. Use Parrot/Kali for the complete lab enumeration workflow.

No prebuilt native executable, code-signing certificate or automatic updater is claimed. The console entry `atlas-desktop --browser` keeps an explicit Ctrl+C shutdown path for the local browser fallback. The release provides source, a Python wheel, installer scripts and checksums; Python is a prerequisite. The original code is public source with all rights reserved, not an open-source license grant. See [LICENSE](../LICENSE).

## Optional computation server

Open **Tools → App & server** in the installed app. Enter the HTTPS address and operator password of an Atlas 0.9.0+ hosted server. A private server CA can be supplied as a public PEM certificate; TLS verification cannot be bypassed. Connection/sign-in state is held only in process memory and must be re-established after restart.

The first offload operation is **cached advisory correlation**. The server operator loads public NVD/OSV/GHSA snapshots through the existing vulnerability tools. In the client, choose a local identity, prepare or enter up to 20 exact software identities, review the JSON and enable the sharing checkbox. Only CPE or package ecosystem/name/version fields cross the boundary. Private package names may themselves be sensitive; review them. No target address, local asset/workspace ID, target credential, raw evidence or full assessment is sent.

The server matches at most 5,000 loaded advisories under a time bound and reports missing/unknown applicability and truncation. It makes no target requests or public lookups for this operation. The client can **Retain analysis as evidence**, then **Prepare finding from retained analysis**. Evidence is inferred and the finding remains an operator draft requiring applicability, patch and impact validation. No result is automatically promoted to a confirmed vulnerability.

The companion does not yet provide distributed scanning, arbitrary compute jobs, full workspace synchronization, or remote ownership of local investigations. Local collection/import/reports work while it is disconnected. Existing server-side assessments are not moved or merged automatically into a new local installation.

## Updates, closing and recovery

**App & server → Check for updates** contacts only the fixed Atlas GitHub release endpoint, on demand. It reports the stable version and opens only its verified repository release page when requested. It downloads or executes no update code. The check does not share assessment data. Failed checks leave local work available.

Before updating: finish/cancel active work, close Atlas, and back up the separate data folder while stopped. Extract the reviewed new release and run its installer again with the same runtime prefix. Existing assessments remain in the separate data folder. Restore the previous runtime if an update fails; preserve the data and any schema backup. The single-instance OS lock prevents two local Atlas processes from opening the same folder. A stale lock file after a crash does not prevent a later launch.

Closing the native window stops the listener and closes owned terminals, browser sessions and collectors. Persisted work survives reopening; unfinished tests retain interrupted outcomes. Authentication and route-review tokens do not survive. Saved context identifies the installation that collected evidence; reinstalling to another host does not make that historical context current.

The shell rejects remote and file navigation and exposes no application Python API. Use Atlas's separately scoped embedded testing browser for target interaction. Qt runs with the Chromium sandbox; do not use sandbox-disable flags or launch as root. Downloads ask for an explicit destination. At-rest protection is provided by the OS account and disk encryption, with the existing export/redaction limits.

See [execution context](execution-context.md), [investigations](investigations.md), [hosted server setup](hosted-console.md), and [ADR 0010](adr/0010-operator-host-desktop.md).
