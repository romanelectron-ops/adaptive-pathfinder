# Makefile для APF
.PHONY: build build-windows build-linux test clean deps run help

APP     = apf
VERSION = 1.0.0-alpha
OUT     = dist

help:
	@echo "APF — Adaptive PathFinder"
	@echo ""
	@echo "Команды:"
	@echo "  make deps          Загрузить зависимости"
	@echo "  make build         Собрать для текущей платформы"
	@echo "  make build-windows Собрать для Windows (amd64)"
	@echo "  make build-linux   Собрать для Linux (amd64)"
	@echo "  make build-all     Собрать для всех платформ"
	@echo "  make test          Запустить тесты"
	@echo "  make run           Запустить APF локально"
	@echo "  make clean         Очистить dist/"

deps:
	go mod tidy
	go mod download

build:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o $(OUT)/$(APP) ./cmd/apf/

build-windows:
	mkdir -p $(OUT)/windows
	GOOS=windows GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o $(OUT)/windows/$(APP).exe \
		./cmd/apf/
	@echo "Built: $(OUT)/windows/$(APP).exe"

build-linux:
	mkdir -p $(OUT)/linux
	GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o $(OUT)/linux/$(APP) \
		./cmd/apf/
	@echo "Built: $(OUT)/linux/$(APP)"

build-all: build-windows build-linux
	@echo ""
	@echo "All builds complete:"
	@find $(OUT) -type f -name "$(APP)*" | while read f; do \
		echo "  $$f ($$(du -sh $$f | cut -f1))"; \
	done

test:
	go test ./... -v -count=1

test-short:
	go test ./... -short

run: deps
	go run ./cmd/apf/ start

clean:
	rm -rf $(OUT)/
	@echo "Cleaned."

# Создать папку bin/ и напомнить о sing-box
setup-dirs:
	mkdir -p bin/
	@echo ""
	@echo "Создана папка bin/"
	@echo "Скачай sing-box с https://github.com/SagerNet/sing-box/releases/latest"
	@echo "и положи sing-box.exe (Windows) или sing-box (Linux) в папку bin/"
