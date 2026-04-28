@echo off
setlocal

REM Toggle runtime VPN service OFF via local admin API.
set "ADMIN_URL=http://127.0.0.1:9090"
set "BODY={\"enabled\":false}"
where curl >nul 2>&1
if %errorlevel%==0 (
  set "TOKEN_HEADER="
  if not "%MHRVPN_ADMIN_TOKEN%"=="" set "TOKEN_HEADER=-H x-admin-token:%MHRVPN_ADMIN_TOKEN%"
  curl -s -X POST "%ADMIN_URL%/api/service" -H "Content-Type: application/json" %TOKEN_HEADER% --data "%BODY%"
) else (
  powershell -NoProfile -Command ^
    "$h=@{'Content-Type'='application/json'}; if($env:MHRVPN_ADMIN_TOKEN){$h['x-admin-token']=$env:MHRVPN_ADMIN_TOKEN}; " ^
    "Invoke-RestMethod -Method Post -Uri '%ADMIN_URL%/api/service' -Headers $h -Body '%BODY%' | ConvertTo-Json -Depth 4"
)
echo.
pause
