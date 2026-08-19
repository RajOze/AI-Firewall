@echo off
title Sentinel AI Firewall Launcher

echo ===================================================
echo   Starting Sentinel AI Firewall Systems
echo ===================================================

:: 1. Launch Backend API & WebSocket Stream Server in a new PowerShell window
echo [*] Launching FastAPI Backend on http://0.0.0.0:8000...
start "Sentinel AI - Backend Server" powershell -NoExit -ExecutionPolicy Bypass -Command "cd 'E:\AI-Projects\AI-Firewall'; .\.venv\Scripts\Activate.ps1; $env:PYTHONPATH='.;backend'; .\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"

:: Short delay to allow backend socket initialization
timeout /t 2 /nobreak >nul

:: 2. Launch Vite React Frontend in a separate window
echo [*] Launching React Vite Frontend on http://localhost:5173...
start "Sentinel AI - Frontend UI" powershell -NoExit -Command "cd 'E:\AI-Projects\AI-Firewall\frontend'; npm run dev"

echo.
echo [+] All subsystems initiated in separate dedicated windows.