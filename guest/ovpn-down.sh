#!/bin/bash
# Погасить Wildberries-OpenVPN в госте.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"
tmux kill-session -t ovpn 2>/dev/null || true
sleep 1
ip link show tun1 &>/dev/null && ip link del tun1 2>/dev/null || true
rm -f /run/corpvpn/wb.ovpn 2>/dev/null || true
echo "openvpn погашен"
