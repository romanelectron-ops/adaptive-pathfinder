#!/usr/bin/env bash
# Часть B — проверка Kill Switch на Linux (методика B2). Запускать ОТ ROOT (sudo).
# Проверяет инвариант D3/B-04.2: APF трогает только цепочку APF_KS, не чужие правила OUTPUT.
set -uo pipefail
PHASE="${1:-help}"
DIR=/tmp/apf_ks_test; mkdir -p "$DIR"

snap() {
  local name="$1" f="$DIR/$name.txt"
  { echo "=== $name @ $(date -Is) ==="
    echo "--- iptables OUTPUT (правила) ---"; iptables -S OUTPUT 2>&1
    echo "--- цепочка APF_KS ---"; iptables -S APF_KS 2>&1 || echo "(нет цепочки APF_KS)"
    echo "--- внешний IP ---"; curl -s --max-time 8 https://ifconfig.me/ip 2>&1 || echo "(IP недоступен — ОЖИДАЕМО при активном KS с мёртвым туннелем)"
    echo "--- число правил в OUTPUT ---"; iptables -S OUTPUT 2>/dev/null | grep -c '^-A'
  } | tee "$f"
}

case "$PHASE" in
  marker)
    echo "Добавляю ЧУЖОЕ правило-маркер в OUTPUT (имитация docker/fail2ban):"
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "APF_TEST_FOREIGN" 2>/dev/null || \
      iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
    echo "OK. Теперь: -before, включить KS в APF, -during, выключить, -after, -compare"
    ;;
  before) echo "=== BEFORE ==="; snap before ;;
  during) echo "=== DURING (KS активен) ==="; snap during
    echo ">>> Проверь: создалась ли APF_KS и есть ли в OUTPUT прыжок -j APF_KS" ;;
  after)  echo "=== AFTER (KS выключен) ==="; snap after ;;
  compare)
    echo "=== СВЕРКА (инвариант изоляции) ==="
    foreign_before=$(grep -c "dport 22" "$DIR/before.txt" 2>/dev/null || echo 0)
    foreign_after=$(grep -c "dport 22" "$DIR/after.txt" 2>/dev/null || echo 0)
    apf_after=$(iptables -S APF_KS 2>/dev/null | grep -c . || echo 0)
    jump_after=$(iptables -S OUTPUT 2>/dev/null | grep -c "APF_KS" || echo 0)
    echo "Чужое правило (:22) before=$foreign_before after=$foreign_after"
    echo "Остаток APF_KS после выхода: chain_rules=$apf_after jump_in_OUTPUT=$jump_after"
    ok=1
    [ "$foreign_after" -lt "$foreign_before" ] && { echo "[FAIL] Чужое правило исчезло — KS затёр OUTPUT!"; ok=0; }
    [ "$apf_after" -ne 0 ] && { echo "[FAIL] Цепочка APF_KS не удалена"; ok=0; }
    [ "$jump_after" -ne 0 ] && { echo "[FAIL] Прыжок -j APF_KS остался в OUTPUT"; ok=0; }
    [ "$ok" -eq 1 ] && echo "[PASS] Чисто: чужое правило цело, APF_KS и прыжок удалены"
    echo "(убрать маркер вручную: iptables -D OUTPUT -p tcp --dport 22 -j ACCEPT)"
    ;;
  *) echo "Использование: sudo $0 {marker|before|during|after|compare}"
     echo "Порядок: marker → before → (вкл KS) → during → (выкл KS) → after → compare" ;;
esac
