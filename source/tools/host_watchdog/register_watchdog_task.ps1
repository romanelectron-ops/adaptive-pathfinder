<#
register_watchdog_task.ps1 — регистрирует apf_host_watchdog.ps1 как Scheduled Task,
запускается каждую минуту от имени текущего пользователя, работает независимо от
того, жива ли текущая сессия Claude Code.

Запускать из-под администратора (нужно для -RunLevel Highest).
Отменить: tools\host_watchdog\unregister_watchdog_task.ps1
#>

$taskName = "APF-HostWatchdog"
$scriptPath = Join-Path $PSScriptRoot "apf_host_watchdog.ps1"

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 3)

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "APF dead-man's-switch: возвращает хосту рабочий интернет, если контролирующая сессия Claude Code не 'пульсирует' дольше 10 минут." | Out-Null

Start-ScheduledTask -TaskName $taskName

Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName $taskName | Select-Object LastRunTime, LastTaskResult, NextRunTime
