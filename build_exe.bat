@echo off
setlocal

echo ============================================
echo  Tray Status Indicator - Build Script
echo ============================================
echo.

REM Check python is available
where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: Python was not found on PATH.
    echo Install Python 3.9+ from https://www.python.org/downloads/
    echo and make sure to check "Add python.exe to PATH" during install.
    pause
    exit /b 1
)

echo Installing dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo.
echo Building TrayStatusIndicator.exe ...
python -m PyInstaller --onefile --noconsole --name TrayStatusIndicator tray_indicator.py
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Build complete.
echo  Find your app at: dist\TrayStatusIndicator.exe
echo ============================================
pause
