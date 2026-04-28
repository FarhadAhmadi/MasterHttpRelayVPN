param(
  [string]$TaskName = "MasterHttpRelayVPN",
  [string]$ProjectPath = ""
)

if ([string]::IsNullOrWhiteSpace($ProjectPath)) {
  $ProjectPath = Split-Path -Parent $PSScriptRoot | Split-Path -Parent
}

$startBat = Join-Path $ProjectPath "start.bat"
if (-not (Test-Path $startBat)) {
  Write-Error "start.bat not found at $startBat"
  exit 1
}

$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c \"$startBat\""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Auto-start MasterHttpRelayVPN at user logon" -Force | Out-Null
Write-Host "Installed startup task: $TaskName"
