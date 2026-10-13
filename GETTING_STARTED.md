# Getting started with Assessment Atlas 0.2.0

## Open the application

Extract the package into a folder you control. On Windows, double-click `Start.cmd`. Python 3.12 or newer is required; the launcher tries the Python launcher, Python on PATH, then the existing Codex Python runtime. On Linux/macOS run `sh start.sh`. No third-party Python packages or scanners are required.

The app opens at http://127.0.0.1:8765. Keep its terminal running. Ctrl+C closes it; restart to return to saved workspaces. If the port is occupied, run `python -m atlas.server --port 8766`. Only loopback is supported. Do not expose this server on a network.

## Complete an assessment workflow

1. Create a workspace and record authorized targets, exclusions and handling limits. Offline import does not authorize live contact.
2. Choose **Import results**, select a file, and supply testing position, address-space context and missing collection time/version if known. Preview, review warnings, then save. Repeat for more sources.
3. Open **Network map**. Select a node or connection to see normalized evidence, source location, collection/import times, original-file digest, and status/basis. Use source/type/claim filters, zoom and the scrollable canvas. Keyboard users can focus map elements and press Enter.
4. Review identity suggestions. Names and IPs never merge automatically. Inspect both candidates, record evidence/rationale, then link compatible identities. Undo splits them again without discarding observations. Divergent values are retained; different times may explain the disagreement.
5. Review source assertions in **Findings**. Add questions, tests/retests, access and manual findings in **Assessment activity**. Record evidence references and limitations; never credentials. Changing a review status does not independently validate a scanner result.
6. Open **Reports & exports**. Preview the current map filter selection. By default identifiers and free text are withheld. Explicitly include them only for an authorized destination. Download structured JSON, a map SVG with embedded provenance metadata, or HTML that can be printed to PDF. Original files are never embedded. Inspect the downloaded material before sharing.

The synthetic example is a safe way to explore all six input formats. Every result is invented, including apparent findings; no scan is run. Supported field details and common-format examples are in [Supported formats](docs/supported-formats.md).

## Linux device output

For a Linux machine you are authorized to inspect, explicitly run `python tools/capture_linux.py /protected/evidence/device-output.json` on that machine. It invokes only `ip -V`, `ip -j address show`, `ip -j route show table all`, and `ip -j neigh show`, each with a ten-second timeout. It does not scan peers or change state, and refuses to overwrite an existing output file. Review the output for sensitivity and import the resulting `linux-ip/1` bundle. The app never runs this capture helper itself. The helper has synthetic contract tests; equivalent fixed read-only commands produced the actual Linux snapshots used in [Live validation](docs/live-validation.md).

## Storage, backup and deletion

On Windows the default database is `%LOCALAPPDATA%\AssessmentAtlas\atlas.sqlite3`; Linux/macOS use `~/.local/share/AssessmentAtlas/atlas.sqlite3` unless LOCALAPPDATA is set. The app shows its actual path under **Reports & exports**. To select a directory, use `python -m atlas.server --data-dir /your/protected/folder` (quote paths with spaces). Protect the folder with OS access controls and disk encryption; app-level encryption is not implemented.

Keep original input files outside the repository in your controlled evidence store. Atlas records the SHA-256 of imported UTF-8 bytes and their original filename reference, plus sanitized normalized excerpts; it does not retain raw source bytes. Selected long strings are capped at 12,000 characters. Secret scrubbing is best effort.

Version 0.2.0 keeps database schema 1 and does not rewrite historical observations. Nmap forced `up`/`user-set` is now unknown reachability with a configured basis; actual port responses remain separate. Re-importing a prior file under adapter revision 2 creates a new derivation with retained history. Use source-snapshot filters when comparing versions.

Stop the application before copying the database for backup. Restore to an empty data directory with the same application/schema version; preserve the prior database separately. Results exports are reports, not restorable workspace backups. Newer database schema versions are rejected rather than silently rewritten.

Deleting a workspace requires typing its name. It removes the saved workspace, excerpts, imports, records and decisions from the active database, using SQLite secure deletion and compaction. This does not guarantee forensic erase or delete your originals, downloads, snapshots or external backups. Account for those copies under your engagement retention policy.

## Current boundaries

The first release handled bounded text imports and reporting. Version 0.2.0 adds native scoped web collection and exact original checks; full tool/scanner parity remains unfinished. No Nessus credentials, endpoint agents, passive network packet collection or remote collaboration are included. “Nexus” from the product discussion is provisionally interpreted as **Nessus**; no Nexus Repository compatibility is claimed. Read [Verification](docs/verification.md) and [native coverage](docs/native-web-coverage.md) before relying on support or performance claims.

## Native web workbench

Open Web workbench for deliberately scoped native collection, request comparison, parameter tests, interception, authenticated browsing and original checks. [Setup and recovery](docs/web-tools.md) explains optional dependencies and schema-2 backup; [coverage](docs/native-web-coverage.md) distinguishes implemented workflows from unfinished Burp parity. No Atlas endpoint agent or external Burp extension is installed.
