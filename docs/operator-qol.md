# Operator conveniences — 0.6.1

Discovery, testing and documentation use the same assessment context. These improvements reduce repeated setup without starting operations or changing source evidence.

## Target handoffs

Select an identity in Discovery. **Prepare terminal for…** fills its exact reported IPv4 address and reported open TCP ports for service enumeration, where available. Further ports omitted by the input limit are disclosed. Review the expected interface, operation and limits, then preview the route and authorize the run. Preparation never starts a shell, scan or target request. **Copy…** copies an address, with a manual-copy fallback when clipboard access is unavailable.

**Prepare embedded browser** fills a source-reported URL draft, removes query/fragment values, clears the prior CA/authorization input and suggests the selected existing identity for evidence capture. Review the URL, allowed path and public certificate before starting. Stop a running terminal/browser before preparing a different target. Workspace changes clear live controls and stop previous owned resources; a delayed earlier workspace response cannot replace the latest selection.

## Find and review

Findings supports combined title/target/advisory/evidence search, review status, severity and manual/source filters. Counts state how many findings are shown. Manual findings are unrated rather than assigned an invented severity. Empty filtered results are not a clean assessment. **Clear filters** restores all findings; report selection remains independent. Reviews preserve source assertions and history.

Open the tool finder with **Ctrl/Command+K**. Enter opens the first matching tool; arrow keys move between results and Escape returns focus. Recently used tools appear first for an empty query and as shortcuts in Tools. Only up to six known tool names are stored in the accessing browser's preferences, without target details, excerpts or credentials. Finder shortcuts do not intercept terminal or embedded-browser input.

## Keep documentation moving

An unfinished assessment record stays in memory in its browser tab, separately for each workspace, while changing views/workspaces or refreshing collected results. Its selected identity, type, text, references and status are retained. **Ctrl/Command+S**, while a record field is focused, saves through the ordinary record form. Edits made during a pending save remain an unfinished draft. Repeated shortcut presses while a save is in progress do not submit another record.

Save before reloading, closing the tab or signing out: drafts are transient, not durable autosave or a backup. Excerpts and credentials are not stored in browser preferences. Evidence-to-finding handoff returns to an existing unfinished record before saving another excerpt, avoiding silent replacement. After saving that record, return to Evidence to finding; the selected excerpt remains available. Saved findings remain in the assessment normally.

## Browser workspace

Browser setup collapses after a successful start; the current sanitized page URL and active controls remain visible. Target/scope inputs are locked until Stop. **Page within reviewed scope → Go** deliberately navigates through the existing server scope guard; another origin/path remains blocked. The input is a navigation draft, separate from the displayed current URL.

**Prepare authenticated scan** retains the browser's originally reviewed URL/path/CA context and clears scan authorization/session selection. Protected check URL, signed-in marker and transient cookie verification remain required. Stop restores editable setup and clears browsing authorization. The execution host and HTB VPN requirement are unchanged.

## Verification boundary

[QoL browser acceptance](../tests/qol-ui.cjs) uses real Edge, separate synthetic workspaces and an owned loopback page. It exercises handoffs without collection, keyboard recovery, findings/reports, workspace and save interruption, draft overwrite protection, scoped navigation, authenticated preparation, stop and desktop/mobile reflow. [Verification](verification.md) and the exact packaged-revision receipt record regression and private Ubuntu acceptance. This is an implementation walkthrough, not a real operator usability study, accessibility certification or real HTB assessment. Schema 2 and prior assessment/evidence semantics are unchanged.
