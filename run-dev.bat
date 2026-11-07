@echo off
echo ========================================================
echo        JSLEAKHUNTER — Starting Development Mode
echo ========================================================
echo.

if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    call .\.venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo [*] Starting Python Backend on http://127.0.0.1:5000...
start "JSLeakHunter Backend" cmd /k ".\.venv\Scripts\python.exe js.py --web 5000"

timeout /t 2 /nobreak >nul

echo [*] Starting Vite Frontend on http://127.0.0.1:5173...
start "JSLeakHunter Frontend" cmd /k "npm.cmd run dev"

echo.
echo [+] Development environment launched!
echo [+] Browser UI: http://127.0.0.1:5173
echo ========================================================

