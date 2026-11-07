@echo off
echo ========================================================
echo        JSLEAKHUNTER — Starting Production Mode
echo ========================================================
echo.

if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    call .\.venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo [*] Building optimized production React bundle...
call npm.cmd run build

echo.
echo [*] Starting Unified Server on http://127.0.0.1:5000...
.\.venv\Scripts\python.exe js.py --web 5000

