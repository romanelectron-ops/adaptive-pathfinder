#!/usr/bin/env bash
set -e
VERSION="1.0.0-alpha"

echo "=== APF GUI Build Script ==="

# Проверяем зависимости
for cmd in go node npm; do
  command -v $cmd &>/dev/null || { echo "ERROR: $cmd not found"; exit 1; }
done

# Устанавливаем Wails если нет
command -v wails &>/dev/null || {
  echo "Installing Wails..."
  go install github.com/wailsapp/wails/v2/cmd/wails@latest
}

cd "$(dirname "$0")/../gui"

echo "[1/3] Frontend dependencies..."
cd frontend && npm install && cd ..

echo "[2/3] Building..."
wails build -ldflags "-X main.Version=$VERSION"

echo "[3/3] Packaging..."
mkdir -p ../dist/gui
cp build/bin/APF* ../dist/gui/ 2>/dev/null || true

echo "Done: dist/gui/"
