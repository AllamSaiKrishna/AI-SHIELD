@echo off
title AI-SHIELD SOC Production Launcher
color 0B
cls
echo ============================================================
echo   AI-SHIELD: AI-Powered Intrusion Detection ^& Prevention
echo ============================================================
echo Starting production WSGI server and opening SOC console...
echo.

py serve.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Encountered an issue with 'py'. Trying 'python'...
    python serve.py
)

pause
