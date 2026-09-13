@echo off
title Launch Direct Upload Testbed & Storage
cd /d "%~dp0"

echo =======================================================
echo   Launching Direct Cloud Upload Test Environment
echo =======================================================
echo 1. Starting MinIO Local Storage (Port 9000)...
start "MinIO Local Storage" cmd /k "call storage_mock\run_minio.bat"

echo 2. Waiting 3 seconds for MinIO to initialize...
timeout /t 3 /nobreak >nul

echo 3. Initializing S3 Bucket & CORS Policy...
.\.venv\Scripts\python.exe storage_mock\init_storage.py

echo 4. Starting FastAPI Test Web Application (Port 8000)...
start "Testbed Web Application" cmd /k "call run_testbed.bat"

echo =======================================================
echo   All components started!
echo   Open your browser at: http://127.0.0.1:8000
echo =======================================================
pause
