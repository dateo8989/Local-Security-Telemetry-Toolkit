@echo off
title SOC Console Installer
color 0A

echo ======================================
echo  SOC CONSOLE AUTO INSTALLER
echo ======================================
echo.

REM Step 1 - Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ first.
    pause
    exit /b
)

echo [OK] Python detected

REM Step 2 - Create virtual environment
echo [SETUP] Creating virtual environment...
python -m venv venv

REM Step 3 - Activate venv
call venv\Scripts\activate

REM Step 4 - Upgrade pip
echo [SETUP] Upgrading pip...
python -m pip install --upgrade pip

REM Step 5 - Install dependencies
echo [SETUP] Installing dependencies...

pip install psutil

REM Step 6 - Done
echo.
echo ======================================
echo  INSTALL COMPLETE
echo ======================================
echo.

echo To run your app:
echo   venv\Scripts\python.exe your_script.py
echo.

pause