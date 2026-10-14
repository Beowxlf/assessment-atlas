# Authenticated scans and advanced tools — 0.3.0

Atlas now crawls and audits with an explicitly verified, transient session. Native findings enter the selected assessment immediately: Findings, logical resource map, immutable evidence, review history and JSON/HTML reports use the same stored records. A source assertion remains scanner-reported after review; record independent validation in assessment activity with its evidence references.

## Run an authenticated assessment

1. Open Web workbench in the intended workspace. Configure exact owned origins/path prefixes, exclusions, testing position, public CA where needed, request/time/depth limits and authority. TLS hostname/CA validation remains enabled; addresses are pinned for each run.
2. Under Scan authentication, set a protected session-check URL and a unique signed-in response text marker. Atlas first requests this URL without credentials: a marker visible anonymously is rejected. A 2xx response containing the marker is required when authenticated. Use an endpoint that cannot log out or mutate data.
3. Use **Build a username and password login** to prepare a JSON/form recipe with optional hidden CSRF and returned bearer token, supply transient Cookie/Authorization headers or an explicit login sequence, or finish signing in through Atlas’s isolated browser and choose **Use signed-in isolated browser cookies**. Cookie snapshots remain in process memory, bound to exact selected origins, including path-specific cookies that do not affect the root URL. Existing browser profiles/trust are untouched. Partitioned cookies and LocalStorage tokens are not automatically copied; supply an explicit bearer header if needed. Browser SSO/MFA is interactive; automated MFA/SSO replay is not claimed.
4. Keep the transient session, select audit checks and whether to follow links. Original response checks are the default. Active probes, anonymous authorization comparisons and explicit non-GET API requests require the active-audit checkbox. Exclude sensitive/unsafe parameter names and paths. Discovered forms are not automatically submitted; provide specific form/JSON requests deliberately.
5. Start crawl and audit. Review request counts, audited endpoints, findings, session refreshes and any partial/failed state. Authentication is checked at start, after at most five intervening requests, on unauthorized/redirected baseline responses and before successful completion. A lost session stops auditing; an explicit login sequence can refresh it at most twice. Every login, verification, control and probe counts against shared rate/request/time limits. Cancellation keeps completed evidence.
6. Choose **Review assessment findings**. Inspect a finding’s source, test and baseline/confirmation controls; add review notes or assessment validation. Findings never require copying through an external bridge or importing a second file.

Sessions expire after one hour or restart. Up to eight can be kept transiently across workspaces; the server enforces workspace ownership. Discarding a saved session does not revoke the independent copy held by an already running bounded scan. Stop that scan to discard its copy. Browser snapshots are taken when requested, not continuously synchronized with later browser changes. No refresh request is sent unless explicitly in the supplied sequence.

Per-run session retention is bounded to one hundred cookies per origin, 4 KiB per cookie, and 512 known secret values / 1 MiB total, including replaced tokens. Exceeding target-cookie limits stops the audit and retains failure metadata instead of expanding credential memory indefinitely.

## Login sequence contract

Up to ten scoped GET/POST requests; redirects need an explicit next request. Tokens can be extracted from a top-level/dotted JSON object path, a hidden HTML field or a named response header. Substitution uses `{{name}}`; top-level JSON string fields are JSON-escaped and form values URL-encoded. Nested arrays/JSON substitutions, browser action recording and automatic login-form discovery are not implemented. Do not place secrets in labels or URLs.

Example with entirely synthetic values; substitute actual owned scoped URLs in the UI:

```json
[
  {"url":"https://owned.example/login","extract":{"csrf":{"from":"hidden","name":"csrf"}}},
  {"url":"https://owned.example/session","method":"POST","headers":[{"name":"Content-Type","value":"application/json"}],"body":"{\"username\":\"synthetic\",\"password\":\"fixture-only\",\"csrf\":\"{{csrf}}\"}","extract":{"bearer":{"from":"json","name":"access_token"}}}
]
```

If a returned bearer token is needed, enter `Authorization: Bearer {{bearer}}` under transient authentication headers. Headers with unresolved placeholders are omitted until the token is extracted. CookieJar applies secure/path/expiry rules; separate origin jars prevent cross-origin/port credential leakage. Authentication origins must be already in scan scope. Auxiliary origins receive no session credentials unless explicitly selected as authentication origins.

Login request/response bodies are always saved as metadata, including when scan body retention is selected. Known credential/cookie/token values are withheld from subsequent excerpts; hidden-input values and sensitive header/structured values are scrubbed by the common adapter. Digests/capture IDs still refer to original captured bodies/requests, while the envelope/artifact digest describes the scrubbed intake. Unknown sensitive content can still evade pattern-based redaction: metadata remains the default and exports need review. Raw session configuration and browser cookie snapshots are absent from databases, reports and run plans. Python/browser process memory is not a secure-erasure guarantee.

## Implemented audit checks

Existing eight header/cookie/error indicators remain available. Five additional selectable families are original, bounded implementations:

| Check | Positive evidence required | Practical limit |
| --- | --- | --- |
| Database error differential | Quote-bearing input causes a recognized database error absent from baseline/neutral control and present again on repeat | Error signatures only; no query control, extraction or comprehensive SQL/NoSQL coverage |
| Template arithmetic | Two distinct unique-marker arithmetic inputs yield the two expected products; baseline/literal control do not | One `{{a*b}}` syntax; engine and impact unqualified |
| HTML reflection | Inert custom element appears verbatim in a captured HTML response | No script execution, DOM-context or browser exploitation proof |
| CORS Origin | Reserved-domain Origin reflected with credential permission | Browser readability, SameSite and data sensitivity unqualified |
| Authorization comparison | Explicit protected marker appears in authenticated and credential-free GET responses | Anonymous comparison only; no object guessing or automatic cross-role/IDOR verdict |

Query/form/top-level JSON scalar insertion points are supported, up to ten per explicit request; token/password/secret/session parameters are excluded. Body/delay/limits and baseline/control references are retained. Findings are deduplicated by origin/path, check and parameter within a run; separate runs remain separate historical evidence. Every completed check is bounded by received, untruncated text. Error/unsupported/truncated responses are not a clean verdict.

Custom response checks are declarative JSON with an ID/name/severity and literal `status`, `body_contains`, or `header` plus `header_equals` conditions (all supplied predicates must match). At most ten rules; severity info/low/medium. No imported code, custom regex, plugin execution or implicit probe runs. OpenAPI 3.0/3.1 JSON inventory is inert: up to thirty direct GET routes, exact current scope only; server declarations and external references are not followed. Parameterized/non-GET/ref-dependent routes are reported for explicit operator requests. No automatic schema authentication or full GraphQL/SOAP support.

## Other advanced native tools

- Multi-position tests: one-position, same-value, aligned sets and all-combination modes across up to five existing query/form/JSON points. Payload sets up to twenty each and 200 combinations total; one baseline then bounded requests, with selected session verification. Processors: Base64, URL, HTML, JSON string. URL parameters are serialized normally after processing, so deliberate URL preprocessing produces an additional encoding layer.
- Decoder: bounded UTF-8 text Base64/URL/HTML/hex/JSON encode/decode and SHA-256; malformed/non-UTF-8 input rejects. Never executes decoded text; no binary file decoder.
- Token sample measurements: 2–5,000 samples; duplicates, length distributions, per-position character distribution/empirical Shannon entropy. Raw samples/characters are not saved. Measurements are not a statistical randomness battery, entropy lower bound or predictability verdict.
- Response interception: scoped HTTP/HTTPS text/JSON/XML responses up to 16 KiB can be edited or dropped. Original upstream evidence is saved first; downstream modifications are separately labeled, correlated to the original and not counted as another target request. Larger, compressed/binary or non-UTF-8 responses bypass this text editor. Framing headers are controlled; body edits discard Content-Encoding. Duplicate editable headers remain unsupported.

This document preserves the 0.3.0 authenticated-scan contract. Version 0.4.0 adds [HTTP/2/3, WebSockets, HTTP/DNS interactions and broader canary checks](protocols-and-callbacks.md). All added probe/control requests pass the same periodic session gate. Full competitor parity remains unfinished; see [current inventory](native-web-coverage.md) for exact support and remaining qualification. Web adapter revision 3 added authentication context and hidden-input scrubbing; revision 4 adds protocol/message/callback derivations; legacy adapter revision 2 stays unchanged. Reimporting an identical historical web event produces a new versioned derivation without overwriting old observations; repeated revision-3 intake deduplicates. The [prior verification](native-web-verification.md) remains evidence for the historical 0.2.0 package, not proof of new authenticated-scan behavior.

Reference inventory checked October 13, 2026: official [authenticated scanning](https://portswigger.net/burp/documentation/scanner/authenticated-scanning), [audit settings](https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings) and [Playwright isolated contexts/cookies](https://playwright.dev/docs/api/class-browsercontext). Atlas implements its own contracts and checks; these references establish no equivalence or reuse rights.
