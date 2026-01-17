@echo off
echo ========================================
echo   SOC Platform - Quick Start
echo ========================================
echo.

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting SOC Platform...
echo Dashboard will be available at: http://localhost:5000
echo.
echo Press Ctrl+C to stop the server
echo.

python app.py

pause
