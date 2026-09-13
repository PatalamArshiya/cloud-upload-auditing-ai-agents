@echo off
title Direct Cloud Upload Testbed (FastAPI)
cd /d "%~dp0"

echo [Testbed] Starting FastAPI Application...
echo [Testbed] URL: http://127.0.0.1:8000
echo [Testbed] Press Ctrl+C to stop.

.\.venv\Scripts\python.exe -m uvicorn testbed_app.app:app --host 127.0.0.1 --port 8000 --reload
pause
