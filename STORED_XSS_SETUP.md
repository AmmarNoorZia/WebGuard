WebGuard Stored XSS handoff

Stored XSS now uses the existing authenticated scan/history/findings/PDF pipeline.
The new route is `POST /api/scans/xss/stored` with only a registered `target_id`.
The Reflected XSS route remains `POST /api/scans/xss`.

**What counts as confirmation**

The scanner discovers the known `/comments` form, obtains its CSRF token, and
submits one harmless comment with a random marker and a private cleanup token.
A second HTTP session retrieves `/comments` without query parameters and must
find the complete saved payload in the record identified by the POST receipt.
The POST response itself is never used as browser execution evidence.

Google Chrome then renders the baseline and retrieved document in separate,
fresh offline contexts. All browser networking is intercepted; only the allowed
same-origin demonstration script can be fetched through the bounded Python
client. CSP stays enabled. Confirmation requires a stored script element,
successful script retrieval, and the alert containing this scan's exact marker.
Old comments' alerts cannot confirm the current test.

An escaped comment with no execution returns `not_detected`. An unavailable
form, failed persistence check, browser failure, or unreliable request returns
`inconclusive`. HTML storage alone never confirms XSS. Severity is high only
for confirmed execution.

Cleanup matches both the unique scanner marker and a SHA-256 hash of its private
token; it cannot remove ordinary comments. Cleanup has a separate request budget
so it is attempted after browser failures and uncertain POST timeouts. Failure
is recorded in evidence and displayed visibly; it does not erase valid execution
proof. Cleanup tokens are never saved in scan evidence or PDF reports.

**Database setup**

No new Supabase migration is required. Continue using the existing
`supabase/schema.sql` and `supabase/migrations/001_scan_results.sql` if setting up
a new database. Both module names fit the existing JSON result and atomic
`save_scan_run` function. JWT verification, user filters, RLS policies, and the
shared scan lock are reused.

Each dummy site's startup adds a `comments` table to its existing local SQLite
database with `CREATE TABLE IF NOT EXISTS`. Existing tables and demonstrations
are preserved. Site A renders comment HTML deliberately; Site B uses Jinja
escaping. Site A's CSP is unchanged: its harmless script is same-origin.

**Run the applications in four PowerShell terminals**

These commands use WebGuard's existing virtual environment. Google Chrome must
be installed locally; no Chromium download is required.

Terminal 1 - Website A:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_a'
$env:PORT = '5001'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' app.py
```

Terminal 2 - Website B:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_b'
$env:PORT = '5002'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' app.py
```

Terminal 3 - WebGuard API:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\backend'
.\.venv\Scripts\python.exe app.py
```

Terminal 4 - React:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\frontend'
npm.cmd run dev
```

If preparing a fresh WebGuard virtual environment, run these once from its
backend directory before starting:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

The lab changes are already installed in both Desktop folders. To reproduce
the same additive installation on this computer:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard'
.\backend\.venv\Scripts\python.exe tools\setup_stored_xss_labs.py
```

**Manual verification**

1. Open `http://127.0.0.1:5173`, sign in, and register/select the root URLs
   `http://127.0.0.1:5001` and `http://127.0.0.1:5002`.
2. On Scans, choose Stored XSS and Website A. Run Stored XSS Scan. Expect
   confirmed/high, `/comments`, a current-marker browser alert in evidence,
   `stored_comment_verified: true`, and cleanup status `removed`.
3. Repeat for Website B. Expect not detected, safely escaped content, no
   current-marker alert, and cleanup status `removed`.
4. Download both PDFs. Check target, endpoint, timestamps, outcome, marker,
   browser proof, severity when confirmed, and recommended mitigation.
5. Reload the page and check Scans, Findings, and Reports. Both saved attempts
   should remain available. This is the outstanding live Supabase check.
6. Choose Reflected XSS and scan both targets again: A confirmed, B not detected.
7. Visit each site's `/comments` page. Ordinary comments should persist while
   successful scanner runs should leave no test comment.

If a result is inconclusive, read its actual outcome. A missing form usually
means the lab needs restarting; a browser error requires installed Chrome and
WebGuard's Python requirements. A failed database save is explicitly marked
unsaved and has no PDF download button.

**Repeat automated checks**

Validation on November 18, 2026:

| Check | Result |
| --- | --- |
| Backend plus real Chrome fixtures and both React flows | 114 passed, 3 skipped, plus 6 passing unittest subtests. |
| Actual Desktop labs with installed Chrome | 3 passed: Reflected A confirmed/B not detected, and Stored A confirmed/B not detected. |
| Website A complete regression suite | 21 passed. |
| Website B complete regression suite | 17 passed. |
| Final Stored XSS regression after CSRF input validation | 31 passed, 1 live test skipped (already verified separately). |
| Required unittest command from `backend/` | 14 passed. |
| Frontend production build | Passed; Vite reports its existing large-bundle advisory. |
| PDF evidence and layout | Positive/negative content assertions passed; both actual-lab reports were rendered and visually checked. |
| Browser history, Findings, Reports, PDF downloads, themes | Passed for both scanner types using a simulated Supabase API/database. |

The three skipped tests are the opt-in actual-lab tests, which passed in the
separate live run. Live Supabase authentication, deployed RLS, and database
persistence were not exercised because no signed-in user session was provided.
API/authentication/ownership/save-failure contracts were tested with mocks;
the real Supabase refresh check remains in the manual guide above.

Stop the two dummy sites before fixture tests because fixtures need ports 5001
and 5002. Keep Vite running for the optional UI tests; port 5000 must be free
for the disposable API.

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\backend'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pytest -q --run-browser-fixtures --run-ui
```

With the actual two Desktop sites running, run live checks separately:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\backend'
.\.venv\Scripts\python.exe -m pytest tests/test_xss_browser.py tests/test_xss_stored_browser.py -q -m live --run-live-labs
```

Each dummy site's existing tests plus its new comments tests can be run with:

```powershell
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_a'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' -m pytest -q
Set-Location 'C:\Users\LENOVO\Desktop\webguard_dummy_site_b'
& 'C:\Users\LENOVO\Desktop\WebGuard\backend\.venv\Scripts\python.exe' -m pytest -q
Set-Location 'C:\Users\LENOVO\Desktop\WebGuard\frontend'
npm.cmd run build
```

**Changed/new WebGuard files**

| File | Purpose |
| --- | --- |
| `backend/app.py` | Adds the Stored XSS endpoint and shares authenticated ownership, persistence, and scan-lock handling with Reflected XSS. |
| `backend/scanners/xss_reflected.py` | Reuses bounded local HTTP and offline browser verification through method/path allowlists and a configurable demo-script path. |
| `backend/scanners/xss_stored.py` | Implements submission, independent persistence verification, current-marker execution proof, outcomes, and precise cleanup. |
| `backend/tests/test_api.py` | Checks that feature metadata advertises both implemented XSS variants. |
| `backend/tests/test_scan_api.py` | Exercises both routes for authentication, ownership, validation, persistence, PDF export, and error handling. |
| `backend/tests/test_xss_browser.py` | Adds SQLite-backed comments to disposable A/B fixtures while preserving Reflected XSS checks. |
| `backend/tests/test_xss_stored.py` | Tests storage requirements, stale markers, malformed receipts, failures, cleanup, and network restrictions. |
| `backend/tests/test_xss_stored_browser.py` | Verifies real Chrome execution on fixtures and Desktop labs, PDF content, and old-comment false positives. |
| `backend/tests/test_frontend_flow.py` | Runs both React scanner flows, downloads positive/negative PDFs, and checks refreshed history, findings, and themes. |
| `frontend/src/pages/Scans.jsx` | Adds separate Reflected/Stored options, correct run buttons, loading text, and shared result history. |
| `frontend/src/components/ScanResult.jsx` | Displays cleanup failures while retaining existing evidence and report controls. |
| `frontend/src/pages/Findings.jsx` | Updates the empty state to mention both scanner options. |
| `frontend/src/pages/Dashboard.jsx` | Updates XSS availability labels to include Stored XSS. |
| `frontend/src/components/Layout.jsx` | Updates shared scanner availability labels. |
| `frontend/src/pages/Settings.jsx` | Updates scanner availability and documents locally installed Chrome. |
| `frontend/src/pages/Targets.jsx` | Updates the availability notice without changing target-management behavior. |
| `tools/setup_stored_xss_labs.py` | Reproduces the additive installation into the two explicitly named Desktop lab folders. |
| `tools/stored_xss_lab/stored_xss_lab.py` | Supplies SQLite comments routes, CSRF validation, and token-protected scanner-only cleanup. |
| `tools/stored_xss_lab/comments.html` | Supplies the common form and deliberately unsafe A/safely escaped B rendering. |
| `tools/stored_xss_lab/xss_stored_demo.js` | Supplies the harmless current-script-marker alert without network or data access. |
| `tools/stored_xss_lab/test_stored_comments.py` | Supplies dependency-free lab regression tests for persistence, escaping, CSRF, and cleanup. |
| `STORED_XSS_SETUP.md` | Documents setup, design, changed files, validation, and manual verification. |
| `XSS_SETUP.md` | Links the earlier Reflected XSS checkpoint guide to the current Stored XSS handoff. |

**Changed/new files outside WebGuard**

Each row lists both actual Desktop copies separately. A/B refers to the folder
suffix in `C:\Users\LENOVO\Desktop\webguard_dummy_site_a` or `_b`.

| Lab / file | Purpose |
| --- | --- |
| A: `app.py` | Registers vulnerable comments support without changing existing routes. |
| A: `stored_xss_lab.py` | Installs the SQLite comments and precise cleanup handlers. |
| A: `templates/comments.html` | Displays saved comments with deliberately unescaped HTML. |
| A: `templates/base.html` | Adds a Comments navigation link. |
| A: `static/xss_stored_demo.js` | Provides CSP-compatible same-origin execution proof. |
| A: `tests/test_stored_comments.py` | Verifies persistence, unsafe rendering, CSRF, and cleanup. |
| A: `tests/test_site_a.py` | Extends the strict static-file allowlist by the new harmless script only. |
| B: `app.py` | Registers protected comments support without changing existing routes. |
| B: `stored_xss_lab.py` | Installs the SQLite comments and precise cleanup handlers. |
| B: `templates/comments.html` | Displays saved comments with safe Jinja escaping. |
| B: `templates/base.html` | Adds a Comments navigation link. |
| B: `static/xss_stored_demo.js` | Provides the identical harmless script that escaped comments cannot execute. |
| B: `tests/test_stored_comments.py` | Verifies persistence, safe rendering, CSRF, and cleanup. |

Startup also adds the comments table to `A: data/site_a.db` and
`B: data/site_b.db`; live testing created and removed one scanner row in each.
SQLite may retain its incremented row counter. Existing data was not reset.

No Supabase SQL, authentication flow, RLS policy, dependency manifest, or PDF
generator was changed. The pre-existing untracked `backend/scanners/discovery.py`
was not changed or executed. Temporary test PDFs, screenshots, and logs are in
ignored `tmp/`; frontend build output remains in ignored `frontend/dist/`.
The implementation handoff originally completed without a Git commit or push.
See [RELEASE_NOTES_v0.4.0.md](RELEASE_NOTES_v0.4.0.md) for the subsequent release
checkpoint and its validation.
