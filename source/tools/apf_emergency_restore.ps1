# apf_emergency_restore.ps1 — одноразовое восстановление интернета (СХ-1, с верификацией/эскалацией).
# Безопасно в любой момент (идемпотентно). Требует прав администратора для netsh.
#
#   .\apf_emergency_restore.ps1                 # тиры: фаервол → DNS (до возврата сети)
#   .\apf_emergency_restore.ps1 -StopApf        # + остановить sing-box/apf/apf-tray/apf-svc в 1-м тире
#   .\apf_emergency_restore.ps1 -StopApf -AllowNuclear   # + ядерный тир (advfirewall reset) как последний рубеж

param([switch]$StopApf, [switch]$AllowNuclear)

. "$PSScriptRoot\apf_safety_lib.ps1"

if (-not (Test-IsAdmin)) {
  Write-Host "[!] Не администратор — netsh может не применить изменения. Запусти PowerShell от админа." -ForegroundColor Yellow
}

Write-Host "[APF] Восстановление интернета (с проверкой возврата egress)..." -ForegroundColor Cyan
$tier = Restore-Internet -StopApf:$StopApf -AllowNuclear:$AllowNuclear
if ($tier -ge 1) { Write-Host "[APF] Сеть восстановлена на тире $tier." -ForegroundColor Green }
else { Write-Host "[APF] Не удалось подтвердить возврат сети (tier=$tier). См. restore.log; попробуй -AllowNuclear или apf_emergency_restore.bat." -ForegroundColor Red }
Write-Host "[APF] Текущее состояние:" -ForegroundColor Cyan
Write-Host (Get-NetState)
exit 0



