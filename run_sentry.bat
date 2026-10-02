@echo off
title NetSentry-NIDS Engine
echo ===================================================
echo       NetSentry - Network Intrusion Engine
echo ===================================================
echo [*] Checking administrator privileges...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Requesting administrative permissions for raw packet capture...
    powershell -Command "Start-Process '%~0' -Verb RunAs"
    exit /b
)

echo [*] Starting NetSentry-NIDS live packet capture...
python nids.py
pause