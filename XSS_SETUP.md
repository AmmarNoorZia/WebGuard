# Reflected XSS vertical slice

WebGuard tests only the registered target's `/search?q` route. The only payload is
an HTML script element loading `/static/xss_demo.js`; the expected alert is
`XSS demo - WebGuard Dummy Site A`. No other scanner is implemented.

## Validation performed in this workspace

For the v0.3.0 checkpoint:

- Offline pytest run: **62 passed, 6 skipped**, plus 6 passing unittest subtests.
  The skipped tests require explicit browser/live/UI opt-in flags.
- Four additional tests passed using installed Google Chrome: the team's running
  Website A returned **confirmed (high)**, Website B returned **not_detected**,
  cross-origin resources were blocked, and restrictive CSP remained effective.
- Existing unittest suite: **14 passed**, including authentication, target CRUD
  and activity contracts.
- Frontend production build passed. Vite emits a bundle-size advisory for the
  existing single bundle (about 558 kB minified); this does not fail the build.
- The team reports that live Supabase scan history and PDF reporting work.
  Automated database/authentication tests use mocks; perform the two-account
  check below to verify deployed RLS policies separately.

During the original implementation, the full fixture/UI run passed 66 tests with
2 live-site tests skipped. It covered React/Flask scanning, saved-result reload,
Findings, Reports, PDF download and both themes using mocked Supabase. PDFs were
rendered and visually inspected. This fixture/UI run is historical and was not
repeated for this checkpoint because the team's real sites occupy ports
5001/5002; the four additional checkpoint tests exercised those real sites and
browser safeguards instead.

Python dependencies are installed in the project's local ignored environment.
The scanner and UI test use installed Google Chrome (`channel="chrome"`,
`headless=True`); no Chromium download is needed. Historical generated fixture
PDFs/screenshots are under `tmp/xss-validation/` and are excluded from Git.

## One-time installation (Windows PowerShell)

Install Google Chrome if it is not already available. Do not run a Playwright
browser download; the scanner and UI test use the installed Chrome channel.

Run from the repository root. `npm.cmd` avoids PowerShell's unsigned `npm.ps1`
restriction. Calling the virtual environment's Python directly avoids activation
policy changes.

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
python -m venv backend\.venv
& .\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
Set-Location frontend
npm.cmd ci
```

Existing `backend/.env` and `frontend/.env` remain unchanged. If setting up a new
checkout, copy the corresponding `.env.example` files and supply the existing
project URL and publishable key. Never supply a service-role/secret key. Keep
credentials out of Git. No real user credentials or JWTs are needed by offline
tests.

## Apply the additive SQL migration manually

1. Open the existing Supabase project's **SQL Editor**.
2. If the foundation has not been installed, run `supabase/schema.sql` first.
3. Open `supabase/migrations/001_scan_results.sql` locally; paste its complete
   contents into a new SQL Editor query and click **Run**.
4. Verify the new `scan_runs` and `security_findings` tables and
   `save_scan_run(uuid,jsonb)` function exist, with RLS enabled on both tables.

The migration adds tables, indexes, own-user select/insert policies and a
security-invoker function. It does not alter or delete targets, activity or auth
data. The function saves the scan and observation atomically under the caller's
JWT. Negative and inconclusive observations are stored with explicit statuses;
they are not counted as confirmed vulnerabilities. Target snapshots preserve
report details if a target is later removed. No migration is applied automatically.

For live RLS verification, use two separate test accounts: create and scan a
target as account A, then confirm account B sees none of A's targets, scans,
findings or reports. Calling A's report URL with B's JWT must return 404.
Automated offline tests check backend ownership filters; they do not execute
Supabase's PostgreSQL policies.

## Start the services in separate terminals

Backend, terminal 1:

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
Set-Location backend
& .\.venv\Scripts\python.exe app.py
```

Frontend, terminal 2:

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard\frontend
npm.cmd run dev
```

Open `http://127.0.0.1:5173`. The Vite proxy connects `/api` to the main backend
on `127.0.0.1:5000`.

The team's Website A/B folders are absent from this workspace. Obtain those
separate subprojects from your teammates; no existing vulnerabilities or
protections were changed. The following commands assume each Flask entry point
is `app.py`. Replace the two absolute example paths with the actual entry points
and install any additional dependencies those subprojects require.

Website A, terminal 3:

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
& .\backend\.venv\Scripts\python.exe -m flask --app "C:\path\to\WebsiteA\app.py" run --host 127.0.0.1 --port 5001
```

Website B, terminal 4:

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
& .\backend\.venv\Scripts\python.exe -m flask --app "C:\path\to\WebsiteB\app.py" run --host 127.0.0.1 --port 5002
```

Verify A serves `/search?q=normal` and `/static/xss_demo.js`, with the documented
alert in the demonstration script. B must escape search input. Do not weaken
either site's escaping or CSP to satisfy a test.

## Automated checks

Offline pytest tests (HTTP, browser proof and Supabase are mocked where needed):

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard\backend
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Installed Google Chrome with disposable documented-behavior fixtures (ports 5001/5002
must be free; tests refuse to replace running websites):

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
Set-Location backend
& .\.venv\Scripts\python.exe -m pytest -q --run-browser-fixtures
```

Full React/browser flow with disposable Flask API, in-memory database and A/B
fixtures: start **only Vite** first; ports 5000, 5001 and 5002 must be free. The
frontend's existing Supabase URL must be configured. Real Supabase auth responses
are intercepted, and no database or credentials are modified.

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
Set-Location backend
& .\.venv\Scripts\python.exe -m pytest -q --run-browser-fixtures --run-ui
```

Real team websites (start A on 5001 and B on 5002 first; these tests do not start
or modify them):

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard
Set-Location backend
& .\.venv\Scripts\python.exe -m pytest -q -m live --run-live-labs
```

Frontend production build:

```powershell
Set-Location C:\Users\LENOVO\Desktop\WebGuard\frontend
npm.cmd run build
```

## Manual acceptance test

1. Apply the migration, start all four services, and log in with a real Supabase
   account. Preview/demo mode intentionally cannot run scans.
2. In **Targets**, register `Website A` at `http://127.0.0.1:5001` and `Website B`
   at `http://127.0.0.1:5002`. Registration itself performs no probe.
3. In **Scans**, select A and click **Run Reflected XSS Scan**. Expect a loading
   message, followed by **confirmed**, high severity, `/search`, actual HTTP
   status, and execution evidence. Evidence must show the injected script tag,
   a test alert matching the expected text, and no matching baseline alert.
4. Select B and run the same test. Expect **not detected**, no severity, escaped
   reflection and no test alert. This is a statement about this one test only.
5. Refresh **Scans**. Both saved results must remain. **Findings** shows both
   labeled observations, their evidence and remediation. Only confirmed results
   count as verified findings. Lists are limited to the latest 100 records.
6. In **Reports**, download the PDF for each saved attempt. Confirm the target,
   IDs, real UTC times, scanner, outcome, evidence and mitigation agree with the
   corresponding scan. PDF downloads also appear on result cards.
7. Stop A and retry: expect **inconclusive** with a connection explanation, never
   a confirmed finding. Missing or unavailable Google Chrome also produces an
   inconclusive result with a browser availability explanation. If saving fails, the result is labeled unsaved and PDF is disabled.
8. Check target registration/removal, account sign-out/sign-in, activity and both
   themes still work. Repeat the two-account RLS check described above.

## API and design notes for the viva

- `POST /api/scans/xss` accepts only `{"target_id":"<registered UUID>"}`.
  It verifies the Supabase user, fetches the user's target, enforces the scan
  allowlist, checks storage availability, runs the test, and saves it atomically.
- `GET /api/scans` and `GET /api/findings` reload persisted user-owned results.
- `GET /api/scans/<scan_id>/report.pdf` verifies ownership again and generates a
  report only from the saved snapshot. It never scans the target during export.
- Confirmation requires a unique injected script element, HTTP 200 demo script,
  the exact expected alert in Chromium, and absence of that alert in the normal
  baseline. HTML reflection alone is insufficient.
- The explicit allowlist is HTTP loopback (`127.0.0.1`, `::1`, or localhost
  resolving exclusively to those addresses) on ports 5001/5002. Registered paths
  may only be root or `/search`, without query/fragment/credentials. Resolved
  localhost is pinned to a numeric loopback address, avoiding later DNS changes.
- Every scanner HTTP request disables proxies/ambient credentials, uses a
  timeout, refuses **all** redirects, and has response-size/request-count limits
  (512 KiB, 6 HTTP requests, a 25-second HTTP budget). A process-local semaphore
  permits one scan at a time. This is a local synchronous lab service, not a
  production queue or distributed rate limiter.
- Chromium stays offline and receives captured search responses at the original
  local URL with CSP preserved. All browser requests are intercepted. Only the same-origin
  demonstration script can be fetched through the same guarded HTTP client;
  other requests, navigation, subframes, websockets and service workers are
  blocked. Existing unrelated scripts/assets are excluded from this focused
  proof, so it is not a full functional assessment of the application.
- A fixed demo-script contract intentionally limits generality. Different alert
  text, routes, required login, encodings, CSP behavior, or asynchronous execution
  may need a future separately reviewed test adapter. No broader XSS-safety claim
  follows from `not_detected`.

## Changed files

New:

- `backend/scanners/xss_reflected.py`: bounded loopback HTTP, reflection analysis,
  baseline comparison, and Chromium execution proof.
- `backend/reporting/pdf.py`: generic escaped, paginated report generation from
  persisted evidence.
- `backend/requirements-dev.txt`: pytest and PDF inspection dependencies.
- `backend/pytest.ini`: test discovery and opt-in browser/live/UI markers.
- `backend/tests/conftest.py`: opt-in test flags.
- `backend/tests/test_xss_reflected.py`: detector and network boundary tests.
- `backend/tests/test_scan_api.py`: ownership, persistence, errors and PDF tests.
- `backend/tests/test_xss_browser.py`: real Chromium fixtures, CSP/boundary checks
  and optional real team-site checks.
- `backend/tests/test_frontend_flow.py`: complete React/Flask/Chromium flow with
  mocked Supabase and real local lab fixtures.
- `supabase/migrations/001_scan_results.sql`: additive scan/findings storage, RLS,
  and atomic save function.
- `frontend/src/lib/useScanData.js`: authenticated persisted-result loading.
- `frontend/src/components/ScanResult.jsx`: shared evidence card and PDF button.
- `XSS_SETUP.md`: installation, migration, operations and acceptance guide.

Modified:

- `README.md`: describe v0.3.0, installed Chrome setup, module status and tests.
- `.gitignore`: exclude browser binaries and generated output/report folders.
- `backend/app.py`: authenticated scan/history/findings/report routes and feature
  status; reuse existing auth/database/activity helpers.
- `backend/requirements.txt`: BeautifulSoup, Playwright and ReportLab.
- `backend/tests/test_api.py`: expect only reflected XSS to be implemented.
- `backend/tests/test_connection_flow.py`: update scanner capability expectation;
  retain existing authentication and CRUD checks.
- `frontend/src/lib/api.js`: authenticated blob download and unsaved-result errors.
- `frontend/src/pages/Scans.jsx`: target selection, real scanning and history.
- `frontend/src/pages/Findings.jsx`: saved labeled observations and evidence.
- `frontend/src/pages/Reports.jsx`: report listing and real PDF downloads.
- `frontend/src/pages/Dashboard.jsx`: replace fixed scan/finding counters with
  saved data and update module availability.
- `frontend/src/pages/Targets.jsx`: update obsolete availability text only.
- `frontend/src/pages/Settings.jsx`: migration/browser setup text.
- `frontend/src/components/Layout.jsx`: update obsolete scanner-status text.
- `frontend/src/styles.css`: small theme-aware additions for result cards.

The pre-existing untracked `backend/scanners/discovery.py` was not changed or
imported. Existing auth context, credentials and base SQL schema are preserved.
The v0.3.0 checkpoint includes only source, tests, documentation and migrations.
Generated reports and the unrelated discovery.py script are excluded. No remote
SQL execution or deployment is performed when preparing this checkpoint.
