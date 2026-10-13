@echo off
title AI-SHIELD Streamlit Console
color 0A
cls
echo ============================================================
echo   AI-SHIELD: Streamlit Security Console Launcher
echo ============================================================
echo Starting Streamlit app...
echo.

py -m streamlit run streamlit_app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Trying python -m streamlit...
    python -m streamlit run streamlit_app.py
)

pause
