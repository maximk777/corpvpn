#!/bin/bash
# Снять то, что накатил route-up.sh. Работает и под sudo, и без.
set -euo pipefail

REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -n "$REAL_HOME" ]] || REAL_HOME="$HOME"
STATE="$REAL_HOME/.local/state/corpvpn"

if [[ "$(id -un)" == "$REAL_USER" ]]; then SUDO="sudo"; else SUDO=""; fi

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
echo "маршруты сняты"
