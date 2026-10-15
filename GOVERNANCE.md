# Governance

Effective baseline: October 12, 2026. This is an owner-led early-stage project. Product intent is established in the [charter](docs/charter.md); architecture details and delivery gates are proposals until their stated decisions are resolved. Publishing these documents does not approve a stack, license, collector, or product release.

Implementation update, October 12: Brayden subsequently authorized a finished initial application, bounded NorthGate testing, code publication and reversible engineering choices. [ADR 0002](docs/adr/0002-local-initial-product.md) records the selected local stack/platform and storage/exports. Implementation uses a feature branch/PR; a runnable private package can be delivered for review. This does not grant public distribution or licensing rights, and no independent owner acceptance of unresolved product decisions is implied.

## Decision rights

Brayden is the product owner and final decision maker. The repository is initially hosted in his personal GitHub account, `Beowxlf`. No additional maintainers or contributors are appointed by this document.

The owner decides scope, priorities, maintainer access, consequential architecture, licensing, distribution, spending, releases, and live collection authorization. A maintainer may review and merge within authority explicitly delegated by the owner. Contributors propose changes and supply evidence; repository access alone is not authority to expand an assessment or deploy software.

Record material decisions in an [ADR](docs/adr/README.md) or the [decision register](docs/roadmap.md). Include rationale, alternatives, consequences, and what would cause reconsideration. Do not turn every reversible edit into an approval request. Within an authorized task, contributors can edit, verify, and prepare a reviewable change; pause only for missing authority or an essential owner decision.

## Change and review

1. State the problem, intended behavior, boundaries, and acceptance evidence in an issue or change description. An issue is optional for a small documentation fix.
2. Use a focused branch and pull request for substantive changes after the initial bootstrap. Include documentation, relevant validation, limitations, and any migration or cleanup required.
3. Review against the charter, evidence invariants, import trust boundaries, and acceptance gates. Identity reconciliation, sensitive storage, live collection, schema migrations, and licensing need explicit owner review unless delegated.
4. The owner or delegated maintainer merges when evidence is adequate. In a solo project the owner may self-review; record that honestly rather than imply independent review. Resolve substantive objections or record why they were declined.

The initial documentation bootstrap may be committed directly to `main`. Urgent corrections may also be made directly by the owner with a reason and follow-up review. Never force-push shared history as a routine fix.

These are process expectations. Branch protection, required checks, CODEOWNERS enforcement, and CI are not configured by this bootstrap. Decide repository enforcement when implementation and collaborators warrant it; do not imply policy text creates technical controls.

## Contributions and disagreement

Use [Contributing](CONTRIBUTING.md) for proposals and review evidence. Discuss behavior and evidence respectfully. The owner resolves unresolved disputes, documenting consequential rationale. There is no voting body or committee at this stage. External code contributions should wait until the owner defines acceptable license and contribution terms; this document imposes no CLA or transfer of rights.

## Releases and changes to governance

A documentation commit is not a product release. Before an application release, identify the exact commit, supported adapters and formats, completed roadmap gates, security limitations, compatibility/migration behavior, packaging validation, and rollback or recovery instructions. The owner approves distribution after reviewing those results. Publish only supported claims and approved synthetic examples; never bundle engagement evidence or credentials.

Security findings follow [Security](SECURITY.md). Material governance changes use the same review path as substantive product changes. Update linked documents together, preserve ADR history, and record the date and rationale for changed authority or policy.

## October 15, 2026 distribution update

The owner explicitly requested an installable operator-host application and a public repository, selecting **public source with all rights reserved**. [LICENSE](LICENSE) records that choice; it grants no open-source reuse rights. Version 0.9.0 adds per-user desktop installation and an optional HTTPS computation companion. This current authorization supersedes earlier statements that public distribution was not authorized. It does not authorize publishing assessment data, issuing an open-source license, or accepting third-party contributions under undefined terms.
