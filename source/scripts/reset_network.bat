@echo off
REM reset_network.bat - Сброс всех сетевых изменений APF
REM Запускай если после APF не работает интернет
setlocal
title APF - Сброс сетевых настроек

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   APF - Сброс сетевых настроек         ║
echo  ╚══════════════════════════════════════════╝
echo.
echo  Удаляем правила файрвола APF...

REM Удаляем все правила APF из файрвола
for %%R in (
    "APF-KillSwitch-allow-loopback"
    "APF-KillSwitch-allow-lan"
    "APF-KillSwitch-allow-vpn"
    "APF-KillSwitch-allow-vpn6"
    "APF-KillSwitch-allow-tun"
    "APF-KillSwitch-allow-probe"
    "APF-KillSwitch-allow-probe6"
    "APF-KillSwitch-block-tcp"
    "APF-KillSwitch-block-udp"
    "APF-KillSwitch-block-out"
    "APF-KillSwitch-allow-local"
    "APF-KillSwitch-allow-dns"
) do (
    netsh advfirewall firewall delete rule name=%%R >nul 2>&1
)
echo  [OK] Правила файрвола удалены

echo.
echo  Восстанавливаем политику файрвола...
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >nul 2>&1
echo  [OK] Политика файрвола: блокировать входящие, разрешить исходящие

echo.
echo  Сбрасываем DNS на автоматический...
REM Для каждого активного адаптера
for /f "tokens=3*" %%a in ('netsh interface show interface ^| findstr /i "connected"') do (
    netsh interface ip set dns name="%%b" source=dhcp >nul 2>&1
)
echo  [OK] DNS переключён на автоматический (DHCP)

echo.
echo  Очищаем кэш DNS...
ipconfig /flushdns >nul 2>&1
echo  [OK] DNS кэш очищен

REM P1-11 (аудит 2026-09-01): отсюда убран "netsh winsock reset".
REM
REM Он противоречил политике, которой придерживается сам APF при сбросе сети
REM (internal/killswitch/reset.go, блок "НАМЕРЕННО НЕ делаем"): winsock reset сбрасывает
REM цепочку LSP и ДО ПЕРЕЗАГРУЗКИ оставляет стек в половинчатом состоянии. Скрипт же сразу
REM после него утверждал "Перезагрузка НЕ нужна" — то есть делал ровно то, что требует
REM перезагрузки, и тут же сообщал обратное.
REM
REM Хуже всего сочетание с назначением скрипта: его запускают, когда интернет УЖЕ не
REM работает. Шаг, который может ухудшить состояние стека, здесь недопустим как рутинный.
REM Сам по себе winsock reset остаётся законным крайним средством — он вынесен в подсказку
REM ниже как ручное действие с честным условием про перезагрузку.

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Готово! Сетевые настройки восстановлены║
echo  ║                                          ║
echo  ║   Перезагрузка НЕ нужна.               ║
echo  ║   Интернет должен заработать.           ║
echo  ╚══════════════════════════════════════════╝
echo.
echo  Если интернет всё равно не работает:
echo  1. Отключись и подключись к WiFi снова
echo  2. Или перезагрузи компьютер
echo.
echo  Крайнее средство, если не помогло ничего выше.
echo  Выполни ВРУЧНУЮ в командной строке от администратора:
echo.
echo      netsh winsock reset
echo.
echo  и ОБЯЗАТЕЛЬНО перезагрузи компьютер сразу после.
echo  Без перезагрузки сеть может не работать вовсе - это нормально для
echo  этой команды. Сюда она не включена намеренно: до перезагрузки она
echo  способна ухудшить ситуацию, а не исправить.
echo.
pause
