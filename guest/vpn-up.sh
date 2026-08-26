#!/bin/bash
# Подключение к корп-шлюзу изнутри песочницы.
# Внешний трафик пойдёт по default-маршруту, то есть в tun-egress -> SOCKS5.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"
: "${VPN_GATEWAY:?задай VPN_GATEWAY (host или host/group)}"
STATE=/run/corpvpn

# Проверка, что egress уже завёрнут в прокси -- иначе VPN пойдёт напрямую.
if ! ip -4 route show default | grep -q "${EGRESS_TUN:-tun-egress}"; then
  echo "ВНИМАНИЕ: default не через ${EGRESS_TUN:-tun-egress}." >&2
  echo "Сначала egress-up.sh, иначе VPN подключится мимо прокси." >&2
  [[ "${FORCE:-0}" == "1" ]] || exit 1
fi

args=(--protocol="${VPN_PROTOCOL:-anyconnect}" --script=/usr/share/vpnc-scripts/vpnc-script)
[[ -n "${VPN_USER:-}" ]]     && args+=(--user="$VPN_USER")
[[ -n "${VPN_OS:-}" ]]       && args+=(--os="$VPN_OS")
[[ "${NO_DTLS:-0}" == "1" ]] && args+=(--no-dtls)   # если у SOCKS5 нет UDP ASSOCIATE
[[ -n "${VPN_EXTRA:-}" ]]    && read -ra extra <<< "$VPN_EXTRA" && args+=("${extra[@]}")

mkdir -p "$STATE"
echo "openconnect ${args[*]} $VPN_GATEWAY"
exec openconnect "${args[@]}" --pid-file="$STATE/vpn.pid" "$VPN_GATEWAY"
