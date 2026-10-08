param([Parameter(Mandatory = $true)][string]$BrokerPath)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $BrokerPath -PathType Leaf)) {
    throw "Bluely Defender broker executable is missing: $BrokerPath"
}

$taskName = 'Bluely Defender Broker'
$action = New-ScheduledTaskAction -Execute $BrokerPath
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
