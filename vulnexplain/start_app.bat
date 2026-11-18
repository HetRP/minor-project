@echo off
setlocal enabledelayedexpansion

REM ==============================================================================
REM VulnExplain — 1-Click Launcher (FastAPI Backend + Vite React Frontend)
REM ==============================================================================

set "SCRIPT_DIR=%~dp0"
set "VENV_ACTIVATE="

if exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    set "VENV_ACTIVATE=%SCRIPT_DIR%.venv\Scripts\activate.bat"
) else if exist "%SCRIPT_DIR%..\.venv\Scripts\activate.bat" (
    set "VENV_ACTIVATE=%SCRIPT_DIR%..\.venv\Scripts\activate.bat"
) else if exist "%SCRIPT_DIR%venv\Scripts\activate.bat" (
    set "VENV_ACTIVATE=%SCRIPT_DIR%venv\Scripts\activate.bat"
) else if exist "%SCRIPT_DIR%..\venv\Scripts\activate.bat" (
    set "VENV_ACTIVATE=%SCRIPT_DIR%..\venv\Scripts\activate.bat"
)

echo ==============================================================================
echo [1/2] Starting FastAPI Backend on http://localhost:8000 ...
echo ==============================================================================

if defined VENV_ACTIVATE (
    echo Activating Virtual Environment: !VENV_ACTIVATE!
    start "VulnExplain - Backend Server" cmd /k "cd /d "%SCRIPT_DIR%" && call "!VENV_ACTIVATE!" && python backend/main.py"
) else (
    echo Warning: Virtual environment not found. Using system Python...
    start "VulnExplain - Backend Server" cmd /k "cd /d "%SCRIPT_DIR%" && python backend/main.py"
)

REM Wait 3 seconds for backend initialization
timeout /t 3 /nobreak >nul

echo.
echo ==============================================================================
echo [2/2] Starting React Frontend on http://localhost:5173 ...
echo ==============================================================================

cd /d "%SCRIPT_DIR%frontend"
if not exist node_modules (
    echo Installing frontend dependencies (one-time setup)...
    call npm install
)
start "VulnExplain - Frontend Dashboard" cmd /k "cd /d "%SCRIPT_DIR%frontend" && npm run dev"
cd /d "%SCRIPT_DIR%"

echo.
echo ==============================================================================
echo VulnExplain is now running!
echo - Backend API:  http://localhost:8000
echo - API Health:   http://localhost:8000/api/health
echo - Web UI:       http://localhost:5173
echo ==============================================================================
pause
