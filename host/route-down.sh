#!/bin/bash
# Снять то, что накатил route-up.sh. Работает и под sudo, и без.
set -euo pipefail

REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -n "$REAL_HOME" ]] || REAL_HOME="$HOME"
STATE="$REAL_HOME/.local/state/corpvpn"

if [[ "$(id -un)" == "$REAL_USER" ]]; then SUDO="sudo"; else SUDO=""; fi

# Пароль sudo спрашиваем заранее: в циклах ниже stderr sudo заглушён.
if [[ -n "$SUDO" ]] && ! sudo -n true 2>/dev/null; then
  echo "нужен sudo -- маршруты и /etc/resolver снимаются от root:"
  sudo -v || { echo "без sudo маршруты не снять" >&2; exit 1; }
fi

if [[ -f "$STATE/routes" ]]; then
  while read -r net; do
    [[ -n "$net" ]] && $SUDO route -n delete -net "$net" >/dev/null 2>&1 && echo "- $net"
  done < "$STATE/routes"
  rm -f "$STATE/routes"
fi

if [[ -f "$STATE/resolver" ]]; then
  while read -r d; do
    [[ -n "$d" ]] && $SUDO rm -f "/etc/resolver/$d" && echo "- DNS для *.$d"
  done < "$STATE/resolver"
  rm -f "$STATE/resolver"
fi

# Вернуть основной DNS Mac (режим DNS_MODE=primary).
if [[ -f "$STATE/dns-primary" ]]; then
  svc="$(sed -n 1p "$STATE/dns-primary")"
  orig="$(sed -n 2p "$STATE/dns-primary")"
  if [[ -n "$svc" ]]; then
    if [[ -n "${orig// }" ]]; then
      $SUDO networksetup -setdnsservers "$svc" $orig && echo "- основной DNS '$svc' возвращён: $orig"
    else
      $SUDO networksetup -setdnsservers "$svc" Empty && echo "- основной DNS '$svc' -> авто (DHCP)"
    fi
  fi
  rm -f "$STATE/dns-primary"
fi
echo "маршруты сняты"
