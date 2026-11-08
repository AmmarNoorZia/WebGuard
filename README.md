# WebGuard — Starter Website (v0.1.0)

**WebGuard** is a locally restricted university web-security assessment platform. This ZIP provides the **main WebGuard interface**, not the two test websites. Its frontend, backend, Supabase integration, authentication flow, UI pages and target-management features are prepared. **It does not yet scan, exploit, or report real vulnerabilities.** SQLi, XSS, headers, cookies and exposed-file checks are placeholders for your team to implement and validate in later phases.

## 1. What is included

- React + Vite dashboard with responsive **dark and light themes** (charcoal/green with a violet accent).
- Login/signup using Supabase Auth (after configuration).
- **Explore Demo** works without a Supabase account, storing only preview targets/activity in your browser. No secure auth is implied in demo mode.
- Target add/list/search/delete. **Only localhost / 127.0.0.1 / ::1 test URLs** are accepted.
- Activity log for target additions and removals.
- Scans, Findings and Reports pages with honest **Not implemented / No findings** states.
- Python Flask REST API for authenticated target and activity CRUD.
- Supabase PostgreSQL schema with per-user Row Level Security (RLS).
- Basic API tests, environment examples, team-oriented Codex instructions.

## 2. Fastest preview — no database or backend needed

Requirements: **Node.js 20+**, npm, VS Code.

```powershell
cd frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173** and click **Explore the live demo**. Browse pages, switch theme, and add/remove local targets. These preview changes use browser localStorage, **not** Supabase. Demo target data is initially populated with `http://localhost:5001` and `http://localhost:5002`; those sites are not included or launched here.

If you have not installed Node.js, use https://nodejs.org/.

## 3. Connect real Supabase accounts and data

**Step A — Create your project.** Create a Supabase project at https://supabase.com/dashboard and open **SQL Editor**. Run the contents of `supabase/schema.sql`. It creates `targets` and `activity_events`, with RLS enabled so users access only their records.

**Step B — Frontend settings.** Copy `frontend/.env.example` to `frontend/.env` and fill:

```env
VITE_SUPABASE_URL=https://YOUR_PROJECT.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=YOUR_PUBLISHABLE_OR_LEGACY_ANON_KEY
```

**Step C — Backend settings.** Copy `backend/.env.example` to `backend/.env` and fill:

```env
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_PUBLISHABLE_KEY=YOUR_PUBLISHABLE_OR_LEGACY_ANON_KEY
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
```

**NEVER copy a Supabase `service_role` key or secret key to the frontend** or commit `.env` files. Only publishable/anon keys should be used in these settings. RLS is the access-control boundary. The backend authenticates the token through Supabase Auth and forwards the *user's* JWT to PostgREST so RLS applies.

**Step D — Start the backend** in a fresh VS Code terminal:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Check **http://127.0.0.1:5000/api/health** (shows `scanner_ready: false`).

**Step E — Start the frontend** in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173**. The React app proxies `/api` calls to Flask on port 5000.

**Step F — Create an account.** On the login screen, choose **Create account**. If Supabase has email confirmation enabled, confirm the email before signing in. Then use the targets page to add `http://localhost:5001` and `http://localhost:5002` once those test websites have been started separately.

> If authenticated CRUD fails, check both `.env` files, confirm `supabase/schema.sql` was applied, inspect the Flask terminal, and verify the login email was confirmed if required.

## 4. Project structure

```text
WebGuard_Starter/
├── frontend/
│   ├── src/
│   │   ├── components/        # Sidebar, branding, modals, common UI
│   │   ├── contexts/          # Authentication, theme, data, notifications
│   │   ├── lib/               # Supabase client, API calls, module metadata
│   │   ├── pages/             # Dashboard, Targets, Scans, Findings, Reports, Activity, Settings
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── .env.example
│   ├── package.json
│   └── vite.config.js
├── backend/
│   ├── app.py               # Authenticated Flask API — NO scanners yet
│   ├── tests/test_api.py
│   ├── .env.example
│   └── requirements.txt
├── supabase/schema.sql     # Tables + RLS policies
├── AGENTS.md               # Codex instructions
└── README.md
```

## 5. Planned feature interfaces

- `GET /api/health`: current system health (public, no data exposed).
- `GET /api/features`: shows all five modules with status `planned`.
- `GET /api/me`: validates Supabase session (authenticated).
- `GET /api/targets`: list your targets (authenticated).
- `POST /api/targets`: create a localhost target (authenticated).
- `DELETE /api/targets/:id`: remove your target (authenticated).
- `POST /api/targets/validate`: URL syntax/allowlist validation **without making network requests**.
- `GET /api/activity`: list your target events (authenticated).

Future modules: `backend/scanner/` with separate check files; an orchestrator; verified findings and scan history tables; and PDF export. **Do not enable 'Start scan' until you have implemented and tested actual scanner behavior.**

## 6. Security restrictions for the team

- This starter is for **authorized, locally hosted lab websites only**.
- The backend rejects non-loopback target URLs; the frontend enforces the same rule for preview mode. Scanner modules must independently enforce this allowlist at execution time and after redirects/DNS resolution.
- The app does **not** perform network requests to registered targets. Storing a URL does not scan it.
- Never treat plain text differences as proof of SQL injection. Validate each test against secure and vulnerable versions.
- Never scan random internet websites or third-party services without explicit written authorization.
- Supabase RLS policies must be tested using at least two separately authenticated accounts before relying on them for multi-user isolation.
- Browser demo uses localStorage; it is not a security boundary and must never be confused with real authentication.
- The backend does not provide rate limiting, audit durability, production secret management or deployment configuration. It is a **development starter**, not a production security product.

## 7. Run API tests

```powershell
cd backend
python -m unittest discover -s tests -v
```

No Supabase project is required for the health, feature-flag and URL validation unit tests.

## 8. Team workflow when Codex is available

Open the extracted folder in VS Code, connect it to your GitHub repository, and let Codex read **AGENTS.md** before editing. Work in separate branches. Build one scanner module at a time and verify it on both companion test sites before merging.

Recommended first commit message: `Add WebGuard React Flask Supabase starter`.
