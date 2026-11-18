WebGuard DOM-Based XSS handoff

DOM-Based XSS is the third independent option on Scans, alongside Reflected XSS
and Stored XSS. Its authenticated endpoint is `POST /api/scans/xss/dom` and
accepts only the existing registered `target_id`.

**Design and evidence**

Both Desktop labs now expose `/dom-xss`, which reads `window.location.hash`.
Website A deliberately passes that value into `document.write` while parsing a
normal same-origin JavaScript file. This unsafe HTML sink can execute an injected
same-origin script under the existing `script-src 'self'` policy. Website B uses
`textContent` for the identical input. Neither site's security headers are
weakened. The demonstration script only alerts this scan's random marker; it
does not read private data or make network requests.

The scanner fetches one marker-free HTML response from `/dom-xss` without a query
or fragment. It replays that exact response at the original URL in two fresh,
offline Chrome contexts: one with a plain baseline fragment, one with the test
fragment. Only the site's own driver consumes the fragment. The scanner does
not execute the payload through evaluate, inject a script itself, or bypass CSP.

Confirmation requires the current marker's script element in the resulting DOM,
successful same-origin demonstration-script retrieval, and its exact browser
alert, with no current-marker evidence in the baseline or server response.
Driver completion, correct fragment navigation, and actual output are checked
before a negative result is allowed. Inert HTML and unrelated/old alerts cannot
confirm XSS. Missing pages, script failures, invalid baseline behavior, and
browser failures produce `inconclusive`. A completed test without execution
produces `not_detected`, which does not establish that the entire site is safe.

Browser requests are intercepted. Python's existing bounded client can fetch
only `/dom-xss`, `/static/dom_xss_lab.js`, and `/static/xss_dom_demo.js` from the
validated numeric loopback origin on port 5001 or 5002. Queries, fragments in
HTTP requests, redirects, other origins, unrelated resources, WebSockets, and
service workers are blocked. The URL fragment is supplied only to the browser.

Each result records its real timestamps, endpoint, test list, marker, server
response hash, CSP, baseline/test browser observations, HTTP outcome, mitigation,
and severity when confirmed. The existing scan snapshot supplies the registered
target identifier. Findings, history, and PDF exports reuse the same result.

**Database and existing features**

No SQL migration is required. The existing `module` fields and JSON result store
`xss_dom` without schema changes. Supabase authentication, target ownership,
RLS, atomic persistence, report ownership, and the shared scan lock are reused.
DOM testing is stateless and needs no new SQLite table. Reflected/Stored scanner
implementations, SQLi demonstrations, cookies, and other security modules are
unchanged.

**Exact Windows commands**

The updated lab support is already installed in the two Desktop directories.
Restart any already-running labs and Flask API so they load the new routes.
Use four PowerShell terminals. These commands use the existing WebGuard Python
environment and installed Google Chrome; no browser download is needed.

Website A:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_a'
$env:PORT = '5001'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' app.py
```

Website B:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_b'
$env:PORT = '5002'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' app.py
```

WebGuard API:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\backend'
.\.venv\Scripts\python.exe app.py
```

React:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\frontend'
npm.cmd run dev
```

To reproduce the additive lab installation on this computer:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard'
.\backend\.venv\Scripts\python.exe tools\setup_dom_xss_labs.py
```

**Manual verification**

1. Open `http://127.0.0.1:5173`, sign in, and select/register Website A and B with
   root URLs `http://127.0.0.1:5001` and `http://127.0.0.1:5002`.
2. On Scans select DOM-Based XSS, Website A, then Run DOM-Based XSS Scan. Expect
   confirmed/high at `/dom-xss`, a current-marker test alert, no baseline alert,
   `server_response_contains_marker: false`, and `fragment_sent_to_server: false`.
3. Run the same option against Website B. Expect not detected, no current-marker
   alert, and `text_matches_input: true` with `script_in_output: false` in the
   test browser context.
4. Download both PDFs, reload the page, and inspect Scans, Findings, and Reports.
   Check target identity, endpoint, timestamps, outcome, browser proof, and fix.
5. Repeat with Reflected and Stored XSS. A should confirm and B should return
   not detected for each option. Stored-test cleanup should still be removed.
6. Optional: open either lab's `/dom-xss` page, enter plain text, and submit it.
   The fragment and displayed text should update without server reflection.

An inconclusive result explains the actual blocker. HTTP 404 on `/dom-xss`
usually means a lab needs restarting; API 404 can mean the WebGuard backend
needs restarting. Browser errors require installed Chrome and the existing
Python requirements. A failed save is explicitly unsaved and has no PDF button.

**Repeat automated verification**

Validation on November 18, 2026:

| Check | Result |
| --- | --- |
| Full backend, installed-Chrome fixtures, and all three React flows | 172 passed, 4 skipped, plus 6 passing unittest subtests. |
| Actual Desktop applications on fresh IPv6 loopback servers | 4 passed: Reflected, Stored, and DOM-Based XSS confirmed on A and not detected on B. |
| Required backend unittest command | 14 passed, including authentication and target CRUD contracts. |
| Shared scan API/report checks after pagination fix | 49 passed across all three scanner types. |
| Website A complete regression suite | 23 passed. |
| Website B complete regression suite | 19 passed. |
| React production build | Passed with the existing Vite large-bundle advisory. |
| History refresh, Findings, positive/negative PDF downloads, themes | Passed for all three options with a simulated Supabase API/database. |
| DOM PDF layout | Both actual-lab reports rendered and visually checked after keeping headings with following text. |
| Credential/exclusion audit and whitespace check | Passed; no credential values found in project files. |

The four skipped tests in the full suite are the opt-in actual-lab tests; all
four passed in the separate live run. Existing IPv4 services were left running;
the actual-lab verification started and stopped only fresh IPv6 instances from
the same Desktop source folders, using the same allowed ports and default CSP.
Stored regression probes cleaned up their own rows; zero scanner-created
comments remained in either existing database after verification.

Live Supabase authentication, deployed RLS, and real database persistence were
not verified with a signed-in user session. Their API contracts were exercised
with mocks, including ownership, expired sessions, save errors, and history
reload. Complete the real Supabase refresh/report check in the manual guide
after restarting the applications.

Keep Vite running for UI tests. Disposable fixtures choose a free IPv4 or IPv6
loopback pair on ports 5001/5002 and refuse to replace existing applications.
Only each isolated UI browser's API calls are routed to its disposable Flask
server; the running WebGuard API and Vite proxy are unchanged.

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\backend'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pytest -q --run-browser-fixtures --run-ui
```

With restarted actual labs running on IPv4 loopback:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_xss_browser.py tests/test_xss_stored_browser.py tests/test_xss_dom_browser.py -q -m live --run-live-labs
```

For actual labs deliberately served on IPv6 loopback, add
`--live-lab-host=::1`. This option accepts only `127.0.0.1` and `::1`; scanner
authorization remains restricted to the same two ports.

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_a'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' -m pytest -q
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_b'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' -m pytest -q
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\frontend'
npm.cmd run build
```

**New and modified WebGuard files**

| File | Purpose |
| --- | --- |
| `backend/scanners/xss_dom.py` | Implements bounded local DOM testing, baseline comparison, browser-only attribution, and evidence-based outcomes. |
| `backend/app.py` | Adds the DOM scan endpoint and feature metadata while reusing authenticated scan execution and persistence. |
| `backend/reporting/pdf.py` | Keeps section headings with their following text when longer DOM evidence spans pages in the shared PDF report. |
| `backend/tests/test_xss_dom.py` | Covers confirmation requirements, false positives, failures, DNS pinning, redirects, and request scope. |
| `backend/tests/test_xss_dom_browser.py` | Verifies actual Chrome DOM execution, safe rendering, CSP, stale alerts, local isolation, and PDF content. |
| `backend/tests/test_scan_api.py` | Extends existing authentication, ownership, persistence, PDF, and failure checks to DOM scans. |
| `backend/tests/test_api.py` | Verifies all three XSS modules are advertised. |
| `backend/tests/test_xss_browser.py` | Adds the DOM lab to existing fixtures and safely selects free loopback addresses for regression testing. |
| `backend/tests/test_xss_stored_browser.py` | Supports fixture-selected and explicitly configured loopback origins without changing Stored XSS assertions. |
| `backend/tests/test_frontend_flow.py` | Exercises all three scanner options, refreshed history, findings, PDFs, and themes with an isolated API. |
| `backend/tests/conftest.py` | Adds a loopback-only host choice for opt-in live-lab tests. |
| `frontend/src/pages/Scans.jsx` | Adds the third independent option, API selection, explanation, and loading text. |
| `frontend/src/pages/Findings.jsx` | Mentions DOM scans in the existing empty state. |
| `frontend/src/pages/Dashboard.jsx` | Updates XSS availability labels. |
| `frontend/src/components/Layout.jsx` | Updates shared availability labels. |
| `frontend/src/pages/Settings.jsx` | Updates the scanner availability notice. |
| `frontend/src/pages/Targets.jsx` | Updates the notice without changing target-management behavior. |
| `tools/setup_dom_xss_labs.py` | Reproduces the additive installation into the two authorized Desktop labs. |
| `tools/dom_xss_lab/dom_xss_lab.py` | Registers the static, marker-free DOM page under the sites' existing security hooks. |
| `tools/dom_xss_lab/dom_xss.html` | Supplies the same browser-input interface with the appropriate A/B rendering mode. |
| `tools/dom_xss_lab/dom_xss_lab.js` | Demonstrates unsafe document.write on A and safe textContent on B. |
| `tools/dom_xss_lab/xss_dom_demo.js` | Provides harmless, current-marker-only execution proof. |
| `tools/dom_xss_lab/test_dom_xss.py` | Verifies no server reflection, asset availability, local restrictions, and unchanged CSP. |
| `DOM_XSS_SETUP.md` | Documents design, setup, file changes, validation, and manual testing. |

**New and modified files in the Desktop labs**

Each A/B entry below is a separate actual file under
`C:\Users\LENOVO\Desktop\webguard_dummy_site_a` or `_b`.

| Lab / file | Purpose |
| --- | --- |
| A: `app.py` | Registers the vulnerable DOM page while preserving existing route handlers. |
| A: `dom_xss_lab.py` | Adds the local-only, marker-free page route. |
| A: `templates/dom_xss.html` | Presents the DOM exercise in unsafe mode. |
| A: `templates/base.html` | Adds a DOM input navigation link. |
| A: `static/dom_xss_lab.js` | Reads the fragment and deliberately processes it through document.write. |
| A: `static/xss_dom_demo.js` | Shows harmless same-origin execution proof under unchanged CSP. |
| A: `tests/test_dom_xss.py` | Tests the new page, local guard, server-input isolation, and assets. |
| A: `tests/test_site_a.py` | Extends the strict static-file allowlist by the two harmless DOM scripts. |
| B: `app.py` | Registers the protected DOM page while preserving existing route handlers. |
| B: `dom_xss_lab.py` | Adds the local-only, marker-free page route. |
| B: `templates/dom_xss.html` | Presents the same DOM exercise in safe mode. |
| B: `templates/base.html` | Adds a DOM input navigation link. |
| B: `static/dom_xss_lab.js` | Reads the same fragment and displays it using textContent. |
| B: `static/xss_dom_demo.js` | Provides the same script, which text output does not execute. |
| B: `tests/test_dom_xss.py` | Tests the protected page, local guard, server-input isolation, and assets. |

No credentials, dependency manifests, Supabase SQL, or unrelated
security detector implementations were changed. The pre-existing untracked
`backend/scanners/discovery.py` remains untouched. Generated test PDFs,
screenshots, and logs are under ignored `tmp/`. No commit or push was made.
