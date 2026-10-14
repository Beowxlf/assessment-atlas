# Operator workspace — 0.5.0

The user requested simpler enumeration/discovery and easier tool location, using Cobalt Strike and Burp Suite as references. Atlas keeps its own design and assessment model. The reference patterns are quick access and target tables from [Cobalt Strike's toolbar](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/ui_toolbar.htm), and selected-context handoffs from [Burp's site-map workflow](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/workflow-tools). References checked October 14, 2026. No vendor code, screenshots, icons, assets, branding, session/C2 mechanics or competitor parity claims are included.

## Complete task flow

**Workspace → Discovery → Tools → Findings → Reports.** Six primary sidebar destinations are Workspace, Discovery, Tools, Findings, Evidence and Reports. More workspace views exposes the existing map, activity, imports, web workbench and vulnerability page; the same destinations are reachable through task links. Existing evidence, identity reconciliation and review features remain available.

Discovery presents a searchable/filterable target table, source claim states, finding counts, selected-target evidence, and recent runs/coverage. It includes shortcuts to import collected host/service results, enumerate an explicitly scoped website and review software inventory. Network enumeration starts from supported discovery imports; Atlas does not launch Nmap or scan a network from the target table. Native web discovery uses the existing bounded crawler/path engine.

Selecting a target prepares the next tool. Reported web URLs or HTTP-service-derived URL drafts are labeled; preparation resets live authorization and request/authentication input context. It does not make a target request. An operator must review origins, paths, authentication and limits, then deliberately start collection. A software handoff narrows the inventory view, clears prior scan selection and still requires reviewed software selection. Associations remain evidence-based; names/IPs are not merged.

Tools provides 22 purpose-labeled destinations grouped by Discovery, Testing, Analysis and Assessment. Search accepts tasks and familiar names such as Repeater, Intruder, Sequencer, Collaborator, CVE or authentication; matches open the corresponding native Atlas controls. The header **Find a tool** button and **Ctrl/Command+K** open the same searchable directory. Opening a tool performs local navigation, not a live scan. Web tabs precede configuration, and the authentication editor opens through **Configure authentication** or its tool entry. The selected session remains visible.

## Interaction contract

| Component | Input and feedback | Recovery and keyboard behavior | Data/action contract |
| --- | --- | --- | --- |
| Target table | Search/type filters; selected row and evidence pane | Empty results explain imports/filters; buttons support keyboard activation; focus survives table refresh | Up to 250 visible matching identities; no fabricated wiring or implicit collection |
| Target handoff | Prepares web URL/scope or software inventory | Unknown URLs require explicit input; drafts explain their source limits | Authorization remains unchecked, prior sensitive request inputs are cleared; no target request starts |
| Tool directory | Task/name search with category and purpose | Empty results offer search examples; direct tool buttons, focus on destination or relevant control | Existing tools and findings share the assessment; unavailable engines retain their existing setup messages |
| Tool finder | Header button or Ctrl/Command+K | Search has a visible label; Escape/Close returns focus; selected tool moves focus to its destination | Session-local directory; no external search requests |
| Scan/run feedback | State, request/finding counts, gaps and source inspection | Existing stop controls retain partial evidence; interrupted jobs remain visible | Software and web collection stay within their independent bounds |
| Workspace switch | Clears selected target, search/draft software selection and public disclosure | Existing empty/loading/error states remain available | Prior credentials, target drafts and authorization are not carried into the new workspace |

## Design and validation

Existing type, spacing, teal/neutral colors and component language are preserved. Discovery has a target table with an adjacent inspector at wide widths and stacked cards at smaller widths. The tool directory uses two columns on desktop and one on mobile. Longer addresses/CPEs wrap; tables scroll inside their container. There is no added animation, vendor artwork or inaccessible icon-only navigation.

Verification covers a synthetic browser task from imported discovery through target selection, web preparation, familiar-name tool search, authentication disclosure, software handoff, context switching and mobile layout. It checks no target request started, keyboard focus return, and the existing import/web/authenticated/protocol workflows. This is an implemented interaction review with synthetic walkthroughs, not a real operator usability study or a comprehensive accessibility certification. Keyboard/screen-reader behavior beyond the tested controls remains a manual acceptance task. See [verification](verification.md) and [vulnerability scans](vulnerability-scans.md).

## Linux hosted execution and documentation

The tool directory also opens Embedded terminal, Embedded browser and Evidence to finding. [Hosted console](hosted-console.md) describes the route-checked discovery profiles, interactive browser, authenticated-audit preparation and selected evidence handoff. Operations execute on the Atlas Linux host; the browser client VPN does not supply its route. A reviewed finding draft appears in Findings after saving.
