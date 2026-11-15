# WebGuard v0.3.0 - Reflected XSS Scanner

WebGuard is a university Information Security project for controlled testing of
team-owned, deliberately vulnerable local websites. It uses React + Vite,
Flask, Supabase Auth/PostgreSQL, Requests, BeautifulSoup and Playwright.

## Current implementation

- Supabase login/signup, session persistence and per-user Row Level Security.
- Registered localhost target management and activity history.
- Reflected XSS testing of `/search?q` using the harmless same-origin
  `/static/xss_demo.js` demonstration script.
- Browser execution verification through **installed Google Chrome**, launched
  by Playwright with `channel="chrome"` and `headless=True`. No Chromium download
  is needed for the scanner or browser tests.
- Saved scan history, evidence, Findings and authorized PDF downloads.
- Existing responsive dark/light themes and green/charcoal/violet design.

The team reports these verified results for its separately maintained sites:

| Website | URL | Reflected XSS result |
| --- | --- | --- |
| A | `http://127.0.0.1:5001` | Confirmed - High |
| B | `http://127.0.0.1:5002` | Not detected |

The team also verified Supabase scan history and PDF reporting. Stored XSS,
DOM-based XSS, SQL injection, security headers, sensitive resources and cookie
testing are **not implemented** in this checkpoint.

`confirmed` requires the injected script element, a successful demo-script
response, and the exact alert `XSS demo - WebGuard Dummy Site A` in the test
browser, without the same alert in the normal baseline. Reflection alone is
insufficient. `not_detected` means this controlled test did not demonstrate
execution; it does not establish that a website has no XSS. Failed or unreliable
verification is `inconclusive`.

## Setup (Windows PowerShell)

Requirements: Python 3.11+, Node.js 20+, installed Google Chrome and a configured
Supabase project. The companion Website A/B applications are separate projects
and are not included in this repository.

From the repository root:

```powershell
python -m venv backend\.venv
& .\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
Push-Location frontend
npm.cmd ci
Pop-Location
```

Keep existing `.env` files. On a new checkout only, copy `backend/.env.example`
to `backend/.env` and `frontend/.env.example` to `frontend/.env`, then set the same
Supabase project URL and **publishable key** in both. Never use or commit a
secret/service-role key. Backend requests forward the signed-in user's JWT so
database RLS applies.

In your existing Supabase project's SQL Editor, apply these files in order:

1. `supabase/schema.sql` if the foundation tables are not installed.
2. `supabase/migrations/001_scan_results.sql` for scan runs, findings, own-user
   RLS policies and atomic result storage.

The scanner migration is additive; it does not delete existing targets,
activity or authentication data. No SQL migration is executed by startup.

Backend terminal, from the repository root:

```powershell
Set-Location backend
& .\.venv\Scripts\python.exe app.py
```

Frontend terminal, from the repository root:

```powershell
Set-Location frontend
npm.cmd run dev
```

Open `http://127.0.0.1:5173`. Flask runs at `http://127.0.0.1:5000`; Vite proxies
`/api` to Flask. Start Website A and Website B in separate processes on ports
5001 and 5002 using their own project instructions. Register their root URLs on
**Targets**, sign in, then select a target on **Scans** and click **Run Reflected
XSS Scan**. **Findings** shows persisted observations; **Reports** downloads PDFs
from the saved results. Preview/demo mode cannot run scans.

See [XSS_SETUP.md](XSS_SETUP.md) for detailed setup, test-site commands, evidence
interpretation, two-account RLS verification and manual acceptance steps.

## Tests and build

From `backend/`, run the offline tests and existing unittest contracts:

```powershell
& .\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

Optional real Chrome tests with disposable A/B fixtures (ports 5001/5002 must
be free; running teammates' sites are never replaced):

```powershell
& .\.venv\Scripts\python.exe -B -m pytest -q --run-browser-fixtures
```

To test the team's already running A/B sites instead:

```powershell
& .\.venv\Scripts\python.exe -B -m pytest -q -m live --run-live-labs
```

For the React/Flask browser flow, start only Vite, leave ports 5000/5001/5002
free, and run `python -m pytest -q --run-browser-fixtures --run-ui` with the
backend virtual environment. This test mocks Supabase and stores generated
reports/screenshots in pytest temporary directories; it does not verify live RLS.

From `frontend/`, build the production application:

```powershell
npm.cmd run build
```

## API and source map

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health`, `GET /api/features` | Public health and implemented-module status |
| `GET /api/me` | Validate the Supabase session |
| `GET/POST /api/targets`, `DELETE /api/targets/<id>` | User-owned registered targets |
| `POST /api/targets/validate` | Validate URL syntax without probing it |
| `POST /api/scans/xss` | Scan only the supplied registered `target_id` |
| `GET /api/scans`, `GET /api/findings` | Reload saved user-owned results |
| `GET /api/scans/<id>/report.pdf` | Authorized PDF from persisted evidence |
| `GET /api/activity` | User-owned activity history |

The application lives in `frontend/src/`; authentication remains in
`frontend/src/contexts/AppContext.jsx`. `backend/app.py` reuses the existing
authentication/database helpers. Detection is isolated in
`backend/scanners/xss_reflected.py`, reporting in `backend/reporting/pdf.py`,
tests in `backend/tests/`, and database definitions in `supabase/`.

## Scope and team workflow

Scanner destinations are restricted to HTTP loopback ports **5001 and 5002**,
at root or `/search` without a query, fragment or credentials. Localhost DNS must
resolve only to loopback and is pinned to a numeric address. HTTP redirects are
never followed; requests have time, size and count limits and ignore ambient
proxies/credentials. Chrome stays offline, receives captured responses with CSP
preserved, and loads only the same-origin demo script through the guarded HTTP
client. Cross-origin requests, additional navigation, subframes, websockets and
service workers are blocked.

Never test public/external addresses or use credential theft, exfiltration or
destructive payloads. Keep `.env`, virtual environments, local databases,
browser binaries, temporary files and generated reports out of Git. Use separate
feature branches and review changes before merging into shared `main`.

This is a local educational service, with synchronous scanning and one active
scan per backend process. New scanners, starting with Stored XSS, belong in a
subsequent checkpoint after this version is reviewed and merged.
