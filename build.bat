@echo off
REM ===========================================================================
REM  HybridShield - Windows build script
REM
REM  Produces dist\HybridShield\HybridShield.exe (--onedir, --windowed).
REM
REM  --onedir is deliberate: a onefile build unpacks itself to a temp folder on
REM  every launch, which is slower to start and is a common trigger for
REM  antivirus false positives. --windowed hides the console.
REM
REM  Usage:  build.bat
REM ===========================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ============================================================
echo   HybridShield - build
echo ============================================================
echo.

REM ---- locate Python -------------------------------------------------------
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY (
    where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python was not found on PATH.
    echo         Install Python 3.12+ from https://python.org and tick
    echo         "Add python.exe to PATH".
    goto :fail
)

echo [1/6] Using interpreter: %PY%
%PY% -c "import sys; print('      Python', sys.version.split()[0])"
if errorlevel 1 goto :fail

REM ---- virtual environment ------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    echo [2/6] Creating virtual environment .venv
    %PY% -m venv .venv
    if errorlevel 1 goto :fail
) else (
    echo [2/6] Reusing existing virtual environment .venv
)

set "VPY=.venv\Scripts\python.exe"

REM ---- dependencies -------------------------------------------------------
echo [3/6] Installing dependencies
"%VPY%" -m pip install --upgrade pip --quiet
if errorlevel 1 goto :fail
"%VPY%" -m pip install -r requirements.txt --quiet
if errorlevel 1 goto :fail

REM ---- sanity check -------------------------------------------------------
echo [4/6] Verifying imports
"%VPY%" -c "import PySide6, watchdog, httpx; from scanner.engine import ScanEngine; from ui.main_window import MainWindow; print('      imports OK')"
if errorlevel 1 (
    echo [ERROR] Import check failed. Fix the error above and re-run.
    goto :fail
)

REM ---- clean previous output ---------------------------------------------
echo [5/6] Cleaning previous build output
if exist "build" rmdir /s /q "build"
if exist "dist\HybridShield" rmdir /s /q "dist\HybridShield"

REM ---- build --------------------------------------------------------------
echo [6/6] Running PyInstaller
"%VPY%" -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onedir ^
    --windowed ^
    --name "HybridShield" ^
    --hidden-import "watchdog.observers.winapi" ^
    --hidden-import "watchdog.observers.read_directory_changes" ^
    --collect-submodules "watchdog" ^
    --add-data "scanner\rules;scanner\rules" ^
    --exclude-module "tkinter" ^
    --exclude-module "matplotlib" ^
    --exclude-module "numpy" ^
    --exclude-module "pandas" ^
    main.py
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   BUILD OK
echo ============================================================
echo   Executable: %CD%\dist\HybridShield\HybridShield.exe
echo.
echo   Note: ship the whole dist\HybridShield folder, not just the .exe.
echo   User data (settings, scan history) lives in:
echo       %%LOCALAPPDATA%%\HybridShield
echo.
goto :end

:fail
echo.
echo ============================================================
echo   BUILD FAILED - see the messages above.
echo ============================================================
endlocal
exit /b 1

:end
endlocal
exit /b 0
