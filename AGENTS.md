# Codex project instructions — WebGuard

You are contributing to a university Information Security project. Scope: a safe, locally restricted scanner for intentionally vulnerable websites controlled by the team. The two companion test sites live in separate subprojects and are not part of this starter.

## Architecture
- React + Vite (`frontend/`), custom CSS light/dark theme, lucide-react, React Router.
- Flask (`backend/app.py`) serves `/api/*` and verifies Supabase Auth access tokens through `/auth/v1/user`.
- Supabase PostgreSQL (`supabase/schema.sql`) stores target URLs and activity using per-user RLS.
- The frontend Vite proxy sends `/api` requests to Flask on localhost:5000.
- No scanner is implemented yet. UI must never invent security findings or imply a scan occurred.

## Coding rules
1. Keep changes small and test each feature.
2. Never expose Supabase secret keys or service_role keys to client code or Git.
3. NEVER send attack probes to public/external addresses. Enforce an explicit localhost-only allowlist inside any future scanner, including after redirects and DNS resolution.
4. Prefer clearly named detector modules: SQLi, XSS, Headers, Cookies, Sensitive Resources.
5. Indicate suspected vs confirmed findings; support with reproducible evidence.
6. Test each detector on a known-vulnerable and a protected site; preserve false-positive tests.
7. Do not remove existing dark/light themes, target CRUD, login flows or RLS safeguards.
8. Avoid unnecessary extra dependencies and keep UI consistent with green/charcoal/violet palette.
9. A scan is not complete without a timestamp, target identifier, test list, evidence and outcome. Do not fabricate these values.
10. Prefer explaining each design choice in language suitable for an undergraduate viva.

## Commands
- Frontend: `cd frontend && npm install && npm run dev` (node 20+).
- Backend: `cd backend && pip install -r requirements.txt && python app.py`.
- Backend tests: `cd backend && python -m unittest discover -s tests -v`.
- Frontend build: `cd frontend && npm run build`.

## Team milestone
1. Create two small local test websites A & B separately.
2. Confirm frontend and backend can launch and authenticated target CRUD works.
3. Implement scanning checks one by one, verifying against both sites.
4. Add scan history, findings, report export, and optional bonuses after core detections pass.
