@echo off
setlocal
cd /d "%~dp0"

set "VENV_PY=.venv\Scripts\python.exe"
if exist "%VENV_PY%" (
  "%VENV_PY%" scripts\windows\tray_controller.py
  exit /b %errorlevel%
)

where py >nul 2>&1
if %errorlevel%==0 (
  py -3 scripts\windows\tray_controller.py
  exit /b %errorlevel%
)

python scripts\windows\tray_controller.py
