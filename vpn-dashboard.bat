@echo off
setlocal
cd /d "%~dp0"

REM Open the local admin dashboard in default browser.
set "ADMIN_URL=http://127.0.0.1:9090"
start "" "%ADMIN_URL%"
