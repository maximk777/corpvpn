#!/bin/bash
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"
TUN="${EGRESS_TUN:-tun-egress}"; STATE=/run/corpvpn

systemctl stop corpvpn-tun2socks 2>/dev/null || true
while ip -4 route show default | grep -q .; do ip route del default; done
if [[ -f "$STATE/orig-defaults" ]]; then
  while read -r line; do [[ -n "$line" ]] && ip route add $line 2>/dev/null || true; done < "$STATE/orig-defaults"
fi
[[ -f "$STATE/socks-ip" ]] && ip route del "$(cat "$STATE/socks-ip")/32" 2>/dev/null || true
ip link del "$TUN" 2>/dev/null || true
[[ -f "$STATE/resolv.conf.bak" ]] && cp -a "$STATE/resolv.conf.bak" /etc/resolv.conf || true
rm -rf "$STATE"
echo "egress напрямую:"; ip -4 route show default
