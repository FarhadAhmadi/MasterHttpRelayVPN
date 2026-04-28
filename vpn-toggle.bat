@echo off
setlocal

REM Smart toggle: reads current service state then flips it.
set "ADMIN_URL=http://127.0.0.1:9090"

powershell -NoProfile -Command ^
  "$h=@{}; if($env:MHRVPN_ADMIN_TOKEN){$h['x-admin-token']=$env:MHRVPN_ADMIN_TOKEN}; " ^
  "$s=Invoke-RestMethod -Method Get -Uri '%ADMIN_URL%/api/service' -Headers $h; " ^
  "$next = -not [bool]$s.enabled; " ^
  "$h['Content-Type']='application/json'; " ^
  "$b = @{enabled=$next} | ConvertTo-Json -Compress; " ^
  "$r=Invoke-RestMethod -Method Post -Uri '%ADMIN_URL%/api/service' -Headers $h -Body $b; " ^
  "Write-Host ('VPN is now ' + ($(if($r.enabled){'ON'}else{'OFF'})))"

echo.
pause
