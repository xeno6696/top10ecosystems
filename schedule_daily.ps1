<#
.SYNOPSIS
  Registers (or removes) the Windows scheduled task that runs daily_run.py once a day.

.DESCRIPTION
  The task runs at the given time in THIS MACHINE'S local time zone (set it to Arizona and 07:00 means 07:00 AZT), only while you are
  logged on (that is what lets it play a sound and open a window), and catches up at next logon if the PC was off at that time.
  It uses the project's .venv interpreter via pythonw.exe, so no console window flashes up.

  Nothing is installed until you run this script. Review it first; `-WhatIf` shows what would be registered.

.EXAMPLE
  .\schedule_daily.ps1                 # 07:00 every day
  .\schedule_daily.ps1 -At 06:30       # a different time
  .\schedule_daily.ps1 -Remove         # take the task out again
  .\schedule_daily.ps1 -RunNow         # start the registered task right now, to see it work
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$At = "07:00",
    [string]$TaskName = "top10ecosystems daily KEV watch and report",
    [switch]$Remove,
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Remove) {
    if ($PSCmdlet.ShouldProcess($TaskName, "Unregister scheduled task")) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed '$TaskName'."
    }
    return
}

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started '$TaskName'. Progress: $repo\output\daily\latest_status.txt (written when it finishes)."
    return
}

$pythonw = Join-Path $repo ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $pythonw)) { throw "No $pythonw -- run 'python setup_env.py' first." }

$action   = New-ScheduledTaskAction -Execute $pythonw -Argument "daily_run.py" -WorkingDirectory $repo
$trigger  = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited

if ($PSCmdlet.ShouldProcess($TaskName, "Register daily task at $At (local time: $((Get-TimeZone).Id))")) {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
        -Description "Checks CISA's KEV catalog for changes (sound on a new entry or ransomware flag), syncs the warehouse, exports yesterday's snapshot and rebuilds output\daily_report.html." -Force | Out-Null
    Write-Host "Registered '$TaskName': daily at $At ($((Get-TimeZone).Id)). Results: $repo\output\daily\latest_status.txt"
}
