# ADR 0003: Native web workbench and bounded collection

Date: October 12, 2026. Status: implemented under explicit owner direction; competitor parity remains unfinished.

The owner replaced the initially requested external Burp bridge with native Burp-style capabilities inside Atlas. Preserve the common web-evidence model; do not deliver a Burp extension. Six initial native workflows cover crawling/path/parameter discovery, request editing/replay/comparison, selected-parameter tests, HTTP/HTTPS interception, isolated authenticated JavaScript browsing and explicit original scanner indicators. [Coverage](../native-web-coverage.md) keeps the broader tool inventory and missing acceptance concrete.

Use standard-library scoped HTTP/1.1 transport, frozen DNS address sets with verified TLS hostname, explicit origin/path scope, limits and no automatic redirect/import collection. Extend the inert adapter model with atlas-web/1 and logical web origins/resources/parameters. Keep source assertions, capture time/tool/parser versions, source/body digests, unknown links and independent evidence levels; no identity merging by IP/name.

An authenticated loopback proxy uses optional cryptography to create a memory-only per-session CA, ephemeral OS-protected leaf files and normal verified upstream TLS. An optional Node/Playwright worker opens a fresh Edge context with trust pinned specifically to that proxy CA; no existing proxy/browser/global trust changes. Raw editor buffers and browser credentials remain transient. Metadata is the retention default; optional excerpts remain bounded/best-effort redacted.

Schema 2 provides persisted run plans/outcomes and prevents an old app from treating new fields under old export rules. Automatically create an exact schema-1 SQLite backup before migration; retain evidence/IDs/history, mark unfinished live runs interrupted on restart, never resume them silently. Reports include run limits and default-withheld plans. No endpoint agents or public services are added.

Alternatives: retain only offline import (does not satisfy native tooling); wrap external Burp (owner explicitly rejected direction); add a remote scanning service (unneeded exposure/operational burden); promise full proprietary scanner equivalence (unsupported). Consequences: local Python plus optional TLS/browser dependencies; explicit HTTP/body/protocol/application limits; scanner benchmark and advanced native capabilities remain substantial follow-up work. Qualify protocol hardening, controlled scanner corpus and authentication/session coverage before expanding claims.
