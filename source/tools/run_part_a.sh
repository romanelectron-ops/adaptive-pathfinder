#!/usr/bin/env bash
# Часть A методики — автоматическое тестирование APF. Запускать из source/.
set -uo pipefail
export GOFLAGS=-mod=vendor GOPROXY=off
fail=0
echo "===== A1. Статика ====="
go build ./... 2>&1 | grep -v "apf-svc\|build constraints" | head; echo "build ./... done"
GOOS=windows go build ./cmd/apf ./cmd/apf-svc ./cmd/apf-tray && echo "win-build OK" || { echo "win-build FAIL"; fail=1; }
go vet ./internal/... 2>&1 | grep -v "apf-svc\|build constraints" | head
n=$(gofmt -l internal/ cmd/ | wc -l); echo "gofmt неотформатированных: $n"; [ "$n" -ne 0 ] && fail=1
echo "===== A2. Unit + покрытие ====="
go test ./internal/... > /tmp/a2.txt 2>&1
ok=$(grep -c '^ok' /tmp/a2.txt); fl=$(grep -c '^FAIL' /tmp/a2.txt)
echo "unit: ok=$ok FAIL=$fl"; [ "$fl" -ne 0 ] && { fail=1; grep FAIL /tmp/a2.txt | head; }
echo "===== A3. -race ====="
CGO_ENABLED=1 go test -race ./internal/... > /tmp/a3.txt 2>&1
race=$(grep -c 'DATA RACE' /tmp/a3.txt); rf=$(grep -c '^FAIL' /tmp/a3.txt)
echo "race: DATA_RACE=$race FAIL=$rf"; { [ "$race" -ne 0 ] || [ "$rf" -ne 0 ]; } && { fail=1; grep -E 'DATA RACE|FAIL' /tmp/a3.txt | head; }
echo "===== A4. E2E ====="
go run ./tools/e2e 2>&1 | grep -E "ИТОГ|ПРОЙДЕНЫ|ПРОВАЛЫ"
echo "=========================================="
[ "$fail" -eq 0 ] && echo "ЧАСТЬ A: ВСЁ ЗЕЛЁНОЕ ✅" || echo "ЧАСТЬ A: ЕСТЬ ПРОБЛЕМЫ ❌"
exit $fail
