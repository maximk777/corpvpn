#!/bin/sh
# Обёртка vpnc-script: фиксируем то, что реально пушит шлюз (корп-DNS и домены),
# затем зовём штатный vpnc-script. route-up на Mac читает это из /run/corpvpn/vpn-dns
# -- так мы берём НАСТОЯЩИЙ корп-DNS, а не то, что подсунул systemd-resolved.
if [ "$reason" = "connect" ] || [ "$reason" = "reconnect" ]; then
  mkdir -p /run/corpvpn 2>/dev/null
  {
    echo "DNS=${INTERNAL_IP4_DNS:-}"
    echo "SPLIT_DNS=${CISCO_SPLIT_DNS:-}"
    echo "DEF_DOMAIN=${CISCO_DEF_DOMAIN:-}"
  } > /run/corpvpn/vpn-dns 2>/dev/null || true
fi
exec /usr/share/vpnc-scripts/vpnc-script "$@"
