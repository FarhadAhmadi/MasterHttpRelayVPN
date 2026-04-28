param([string]$TaskName = "MasterHttpRelayVPN")

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  Write-Host "Removed startup task: $TaskName"
} else {
  Write-Host "Task not found: $TaskName"
}
