#!/usr/bin/env bash
# build.sh — сборка APF для всех платформ
set -e

APP="apf"
VERSION="1.0.0-alpha"
OUT="./dist"

echo "=== APF Build Script v${VERSION} ==="
echo ""

mkdir -p "${OUT}"

# Проверяем Go
if ! command -v go &> /dev/null; then
    echo "ERROR: Go не найден!"
    echo "Установи Go 1.22+ с https://go.dev/dl/"
    exit 1
fi

echo "Go version: $(go version)"
echo ""

# Загружаем зависимости
echo ">>> Downloading dependencies..."
go mod tidy
go mod download

# === Windows 64-bit ===
echo ">>> Building Windows AMD64..."
mkdir -p "${OUT}/windows"
GOOS=windows GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUT}/windows/${APP}.exe" \
    ./cmd/apf/
echo "    OK: ${OUT}/windows/${APP}.exe"

# === Windows ARM64 (для Surface и др.) ===
echo ">>> Building Windows ARM64..."
GOOS=windows GOARCH=arm64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUT}/windows-arm/${APP}.exe" \
    ./cmd/apf/
echo "    OK: ${OUT}/windows-arm/${APP}.exe"

# === Linux AMD64 ===
echo ">>> Building Linux AMD64..."
mkdir -p "${OUT}/linux"
GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${OUT}/linux/${APP}" \
    ./cmd/apf/
echo "    OK: ${OUT}/linux/${APP}"

# === Android ARM64 (требует gomobile) ===
echo ">>> Checking Android build (gomobile)..."
if command -v gomobile &> /dev/null; then
    echo "    gomobile found, building Android AAR..."
    mkdir -p "${OUT}/android"
    # gomobile bind -target android -o "${OUT}/android/apf.aar" ./...
    echo "    (Android build requires separate setup — see README)"
else
    echo "    gomobile not found — skipping Android"
    echo "    Install: go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init"
fi

echo ""
echo "=== Build complete ==="
echo ""
echo "Files:"
find "${OUT}" -name "${APP}*" -o -name "${APP}.exe" 2>/dev/null | while read f; do
    size=$(du -sh "$f" 2>/dev/null | cut -f1)
    echo "  ${f} (${size})"
done

echo ""
echo "=== Как использовать ==="
echo ""
echo "Windows:"
echo "  1. Скопируй dist/windows/apf.exe"
echo "  2. Положи рядом папку bin/ с sing-box.exe (см. README)"
echo "  3. Запусти apf.exe — откроется Web UI на http://localhost:9090"
echo ""
echo "Linux:"
echo "  1. chmod +x dist/linux/apf"
echo "  2. ./dist/linux/apf start"
