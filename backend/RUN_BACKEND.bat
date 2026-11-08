@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Run SETUP_BACKEND.bat first.
  pause
  exit /b 1
)
if not exist ".env" (
  echo [ERROR] Create backend/.env based on .env.example.
  pause
  exit /b 1
)
echo Starting WebGuard Flask API at http://127.0.0.1:5000/api/health
".venv\Scripts\python.exe" app.py
pause
