@echo off
cd /d "%~dp0"
if not exist ".env" (
  echo [ERROR] First copy .env.example to .env, then add your Supabase URL and publishable key.
  echo See BACKEND_SETUP_GUIDE.md
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Python 3 is required. Install Python 3.11+ and try again.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Dependency installation failed. Check internet/Python installation.
  pause
  exit /b 1
)
echo.
echo Dependencies ready. Next, run RUN_BACKEND.bat
pause
