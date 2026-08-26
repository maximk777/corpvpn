#!/bin/bash
# Пускаем трафик с macOS через гостя в VPN-туннель (уровень 3).
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"
VPN_TUN="${VPN_TUN:-tun0}"
ip link show "$VPN_TUN" &>/dev/null || { echo "$VPN_TUN не поднят -- сначала vpn-up.sh" >&2; exit 1; }

sysctl -qw net.ipv4.ip_forward=1
add() { iptables "$@" 2>/dev/null && return; }
iptables -t nat -C POSTROUTING -o "$VPN_TUN" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -o "$VPN_TUN" -j MASQUERADE
iptables -C FORWARD -o "$VPN_TUN" -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -o "$VPN_TUN" -j ACCEPT
iptables -C FORWARD -i "$VPN_TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -A FORWARD -i "$VPN_TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

echo "--- подсети, доступные через $VPN_TUN (для host/route-up.sh) ---"
ip -4 route show dev "$VPN_TUN" | awk '{print $1}' | grep -v '^default$'
