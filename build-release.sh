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

# --- Стабильная подпись ---------------------------------------------------
# Без подписи keychain переспрашивает доступ после КАЖДОЙ пересборки (новый хеш).
# Подписываем локальным self-signed сертификатом: у него стабильная подпись,
# поэтому keychain доверяет по ней. Достаточно один раз нажать Always Allow
# после первой подписанной сборки -- дальше молча (в т.ч. фоновый watchdog).
SIGN_ID="corpvpn-codesign"
sign_binary() {
  command -v security >/dev/null && command -v openssl >/dev/null || return 0
  if ! security find-identity -p codesigning 2>/dev/null | grep -q "$SIGN_ID"; then
    echo "создаю локальный code-signing сертификат $SIGN_ID (разово, может спросить пароль)"
    d="$(mktemp -d)"
    cat > "$d/cfg" <<EOF
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=$SIGN_ID
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,codeSigning
EOF
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$d/k.pem" -out "$d/c.pem" -days 3650 -config "$d/cfg" >/dev/null 2>&1 || { rm -rf "$d"; echo "openssl не смог -- без подписи"; return 0; }
    openssl pkcs12 -export -legacy -out "$d/id.p12" -inkey "$d/k.pem" -in "$d/c.pem" -passout pass:corpvpn >/dev/null 2>&1
    security import "$d/id.p12" -k "$HOME/Library/Keychains/login.keychain-db" -P corpvpn -T /usr/bin/codesign -A >/dev/null 2>&1 || echo "import сертификата не прошёл -- без подписи"
    rm -rf "$d"
  fi
  if security find-identity -p codesigning 2>/dev/null | grep -q "$SIGN_ID"; then
    codesign --force --sign "$SIGN_ID" --timestamp=none dist/corpvpn 2>/dev/null \
      && echo "подписан ($SIGN_ID)" || echo "codesign не прошёл -- бинарь без подписи (не критично)"
  fi
}
sign_binary

echo "dist/corpvpn готов (universal). Закоммить его: git add dist/corpvpn"
