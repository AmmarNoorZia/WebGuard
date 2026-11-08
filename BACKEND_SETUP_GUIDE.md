# WebGuard — backend connection guide (Windows)

This patch upgrades the EXISTING WebGuard starter. It does **not** include the vulnerability scanners yet.
Use the same Supabase project in React and Flask. No secret credentials are included.

## 1. Copy files to the right places

If your existing project is `C:\Users\LENOVO\Desktop\WebGuard`, extract this ZIP **into that WebGuard folder** and select **Replace files** when asked.
The ZIP starts with `backend/`, `frontend/`, and `supabase/` — it does NOT include an outer `WebGuard/` folder.
Do NOT delete your `frontend/`, `.git/`, `node_modules/`, or existing code.

## 2. Create Supabase project

Open https://supabase.com/dashboard and create a project. You do not need to manually create tables.
Go to **SQL Editor > New query**. Open `supabase/schema.sql`, paste the whole content, and press **Run**.
This creates `targets`, `activity_events` and per-user Row Level Security policies.

Go to **Project settings > API Keys** (or **Connect**) and copy:
- Project URL: `https://YOUR-PROJECT.supabase.co`
- Publishable key: begins with `sb_publishable_...` (legacy anon key may also work).
Never copy a `secret` or `service_role` key into the React app.

## 3. Create TWO local .env files

Copy `backend/.env.example` to `backend/.env` and replace placeholders:

```
SUPABASE_URL=https://YOUR-PROJECT.supabase.co
SUPABASE_PUBLISHABLE_KEY=sb_publishable_YOUR_ACTUAL_KEY
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
```

Copy `frontend/.env.example` to `frontend/.env` and fill in:

```
VITE_SUPABASE_URL=https://YOUR-PROJECT.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=sb_publishable_YOUR_ACTUAL_KEY
```

Make sure the URL and publishable key match the SAME Supabase project.
Both `.env` files are ignored by Git. Never share the contents of these files.

## 4. Configure email login URLs in Supabase

Go to **Authentication > URL Configuration**:
- **Site URL**: `http://127.0.0.1:5173`
- **Redirect URLs**: add `http://127.0.0.1:5173/**`

In **Authentication > Providers > Email**, keep Email enabled.
For your first simple local test, you may temporarily switch off **Confirm email** so signup signs you in immediately; switch it back on later if desired. If confirmation is on, use a real email inbox and click its confirmation link before signing in.

## 5. Start Flask backend (Terminal A)

From your existing WebGuard folder:

```powershell
cd C:\Users\LENOVO\Desktop\WebGuard\backend
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Or simply double-click `backend/SETUP_BACKEND.bat` once, then `backend/RUN_BACKEND.bat`.
Don't close this terminal while testing.

Open **http://127.0.0.1:5000/api/health**. The JSON should say `"status":"ok"`, `"supabase_configured":true`, `"scanner_ready":false`.
If `supabase_configured` is false, check `backend/.env` and restart Flask.

## 6. Start React frontend (Terminal B)

```powershell
cd C:\Users\LENOVO\Desktop\WebGuard\frontend
npm install
npm run dev
```

Open **http://127.0.0.1:5173**. Vite forwards `/api/*` requests to Flask at port 5000.
If you changed frontend/.env, restart Vite.

## 7. Confirm the five success checks

1. Create account (or sign in after confirming the signup email).
2. Sign in to real workspace (NOT 'Explore the live demo').
3. Open **Target websites** > **Add new target**.
4. Enter: Name `Test Website A`, URL `http://localhost:5001`, environment `Local test`, and click Add. No target server is needed yet: saving a target does not send a network request to that target.
5. Refresh the page: the saved target should remain. In Supabase **Table Editor > targets**, the row should exist. **Activity** should show `Added target: Test Website A`.

A teammate using a different login should NOT see your targets because of RLS.

## 8. Test backend logic without connecting to Supabase

Open another terminal in `backend/` (after dependencies installed):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests mock authentication and database responses; they do not need real Supabase credentials.

## Common problems

- **Sign-in succeeds but target says 'Cannot reach Flask API'**: start Flask on port 5000; confirm Vite is running on port 5173.
- **Account created but cannot sign in**: check email confirmation settings; with confirmations on, verify the email first.
- **403 permission denied**: make sure `supabase/schema.sql` ran successfully and both `.env` files use the same project.
- **502 database operation failed**: inspect the SQL Editor results, make sure `targets` and `activity_events` exist.
- **Supabase configured false**: remove placeholder values and restart Flask.
- **Do not test external URLs**: this starter only accepts localhost / loopback addresses and performs NO vulnerability scanning.

## What files changed

- `backend/app.py` — verified Supabase-JWT target and activity API
- `backend/requirements.txt` — Flask dependencies (existing)
- `backend/.env.example` — backend environment template
- `backend/SETUP_BACKEND.bat`, `RUN_BACKEND.bat`, `RUN_TESTS.bat` — Windows helpers
- `backend/tests/test_connection_flow.py` — mock authentication + CRUD tests
- `supabase/schema.sql` — Supabase tables, grants, RLS policies (safe to rerun)
- `frontend/.env.example` — React environment template
- `frontend/src/pages/Auth.jsx` — signup confirmation redirect
- `frontend/src/pages/Targets.jsx` — correct sample local URL

Everything else in your existing WebGuard project stays unchanged.
