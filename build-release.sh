#!/bin/bash
# Собирает universal-бинарь dist/corpvpn (arm64 + Intel). Для мейнтейнеров.
# Коллегам Go не нужен -- они запускают готовый dist/corpvpn через install.sh.
# После сборки закоммить dist/corpvpn.
set -euo pipefail
cd "$(dirname "$0")"
GO="${GO:-go}"

# unset GOROOT: не зависим от экспортированного в чужом профиле GOROOT.
mkdir -p dist
( unset GOROOT; CGO_ENABLED=1 GOARCH=arm64 GOTOOLCHAIN=auto "$GO" build -o dist/corpvpn-arm64 . )
( unset GOROOT; CGO_ENABLED=1 GOARCH=amd64 CC="clang -arch x86_64" GOTOOLCHAIN=auto "$GO" build -o dist/corpvpn-amd64 . )
lipo -create -output dist/corpvpn dist/corpvpn-arm64 dist/corpvpn-amd64
rm -f dist/corpvpn-arm64 dist/corpvpn-amd64
chmod +x dist/corpvpn
lipo -info dist/corpvpn
echo "dist/corpvpn готов (universal). Закоммить его: git add dist/corpvpn"
