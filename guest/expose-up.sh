#!/bin/bash
# Пускаем трафик с macOS через гостя в VPN-туннели (уровень 3).
# Покрываем оба: tun0 (Cisco) и tun1 (OpenVPN), если подняты.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"

sysctl -qw net.ipv4.ip_forward=1

any=0
for VPN_TUN in ${VPN_TUNS:-tun0 tun1}; do
  ip link show "$VPN_TUN" &>/dev/null || continue
  any=1
  iptables -t nat -C POSTROUTING -o "$VPN_TUN" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o "$VPN_TUN" -j MASQUERADE
  iptables -C FORWARD -o "$VPN_TUN" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "$VPN_TUN" -j ACCEPT
  iptables -C FORWARD -i "$VPN_TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$VPN_TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  echo "--- подсети через $VPN_TUN ---"
  ip -4 route show dev "$VPN_TUN" | awk '{print $1}' | grep -v '^default$'
done
[[ "$any" == 1 ]] || { echo "ни tun0, ни tun1 не подняты" >&2; exit 1; }
