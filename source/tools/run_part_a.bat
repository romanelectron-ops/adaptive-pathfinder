@echo off
REM Часть A методики — автоматическое тестирование APF. Запускать из source\.
setlocal
set GOFLAGS=-mod=vendor
set GOPROXY=off
echo ===== A1. Статика =====
go build ./... 
set GOOS=windows
go build ./cmd/apf ./cmd/apf-svc ./cmd/apf-tray && echo win-build OK || echo win-build FAIL
set GOOS=
go vet ./internal/...
echo --- gofmt ---
gofmt -l internal\ cmd\
echo ===== A2. Unit =====
go test ./internal/...
echo ===== A3. -race (нужен gcc/cgo) =====
set CGO_ENABLED=1
go test -race ./internal/...
echo ===== A4. E2E =====
go run ./tools/e2e
echo ==========================================
echo Проверь выше: 25 ok, 0 FAIL, 0 DATA RACE, E2E ПРОЙДЕНЫ
endlocal
