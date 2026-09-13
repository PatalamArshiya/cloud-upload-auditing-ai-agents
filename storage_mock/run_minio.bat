@echo off
title MinIO Local Object Storage (Direct Upload Testbed)
cd /d "%~dp0"

echo [MinIO] Starting MinIO Local S3-Compatible Server...
echo [MinIO] API Address:     http://127.0.0.1:9000
echo [MinIO] Console Address: http://127.0.0.1:9001
echo [MinIO] Root User:       minioadmin
echo [MinIO] Root Password:   minioadmin
echo [MinIO] Data Directory:  %~dp0data

set MINIO_ROOT_USER=minioadmin
set MINIO_ROOT_PASSWORD=minioadmin
set MINIO_API_CORS_ALLOW_ORIGIN=*

minio.exe server "%~dp0data" --address "127.0.0.1:9000" --console-address "127.0.0.1:9001"
pause
