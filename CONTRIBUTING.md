# Contributing

Start with the [charter](docs/charter.md), [architecture](docs/architecture.md), [roadmap](docs/roadmap.md), and [security policy](SECURITY.md). There are no installation, build, or test commands yet because implementation has not started. Do not invent a development environment or claim a check exists.

## Propose a focused change

Explain the user problem, intended result, boundaries, and how a reviewer can verify it. Link affected acceptance gates or decisions. Label prototypes, proposals, and demonstrated behavior separately. Include sources for current external capabilities and compatibility claims. Use the [ADR template](docs/adr/template.md) for consequential architecture decisions.

For documentation, check links, consistency, factual claims, and status labels. For later implementation, run the checks actually provided by that revision and include their results and limitations. Add meaningful tests for data loss, identity reconciliation, import trust boundaries, or a reproduced fault; avoid tests that merely echo the code.

## Adapter contribution contract for future implementation

Each importer or collector proposal must identify:

- Exact vendor/platform, software versions, input formats or endpoints, and known unsupported variants.
- Evidence mapping to the common model; source field locations, timestamps, vantage point, and configured versus operational meaning.
- Parser/adapter version, input digest, warnings, partial-result rules, and repeat-import behavior.
- Synthetic fixtures for normal, missing, contradictory, malformed, and version-changed inputs. Identify their origin and expected semantic results; redaction alone does not make real evidence safe to commit.
- Maintainer, compatibility policy, license/dependency review, and retirement path if support cannot be sustained.
- For live collection: reviewable commands/requests, scope checks, least-privilege permissions, rate/resource limits, timeout/cancellation, credential handling, output storage, and cleanup. Agents must remain optional.

Unknown format variants must produce clear diagnostics rather than silently invent topology. Recognize and preserve useful partial observations only under an explicit policy. Do not execute commands, scripts, XML stylesheets, external entities, or instructions found in imported content.

## Review and contribution rights

Use focused pull requests after bootstrap and follow [Governance](GOVERNANCE.md). Keep real evidence and secrets out of commits, issues, screenshots, and review attachments. Report vulnerabilities privately under [Security](SECURITY.md).

No product license or external contribution agreement has been selected. Do not copy third-party implementation, tests, assets, or documentation into this project without recording origin, rights, and compatibility and obtaining the owner's applicable decision. Supported data/API integration is a separate question from code reuse.
