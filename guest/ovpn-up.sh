#!/bin/bash
# Поднять Wildberries-OpenVPN в госте на tun1, рядом с Cisco (tun0).
# Запускается в tmux-сессии 'ovpn'; passphrase на ключ подставляет corpvpn через pty.
# Серверу РФ-IP не нужен -> до него идём напрямую (bypass мимо SOCKS).
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"

CFG="${1:?путь к .ovpn}"
STATE=/run/corpvpn
mkdir -p "$STATE"

# bypass: соединение с сервером OpenVPN -- напрямую через исходный шлюз, не в SOCKS.
remote="$(awk '/^remote /{print $2; exit}' "$CFG" 2>/dev/null)"
if [[ -n "$remote" && -f "$STATE/orig-defaults" ]]; then
  rip="$(getent ahostsv4 "$remote" | awk 'NR==1{print $1}')"
  orig_gw="$(awk 'NR==1{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' "$STATE/orig-defaults")"
  orig_dev="$(awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' "$STATE/orig-defaults")"
  if [[ -n "$rip" && -n "$orig_gw" && -n "$orig_dev" ]]; then
    ip route replace "$rip/32" via "$orig_gw" dev "$orig_dev"
    echo "bypass: $remote ($rip) напрямую via $orig_gw dev $orig_dev"
  fi
fi

# openvpn в detached-tmux. --dev tun1 фиксируем, чтобы не столкнуться с Cisco tun0.
# Приватный ключ зашифрован -> openvpn спросит passphrase, его подставит corpvpn.
# ВАЖНО: игнорируем жадный push 10.0.0.0/8 (крадёт корп-DNS/банк-подсети у Cisco)
# и dhcp-option DNS. OpenVPN держит только свои не-10 подсети (172.x и т.п.),
# весь 10.x (включая корп-DNS и wildberries-ресурсы) остаётся за Cisco.
tmux kill-session -t ovpn 2>/dev/null || true
tmux new-session -d -s ovpn \
  "openvpn --config '$CFG' --dev tun1 --auth-nocache --verb 3 --pull-filter ignore redirect-gateway --pull-filter ignore 'route 10.0.0.0' --pull-filter ignore dhcp-option"
echo "openvpn запущен в tmux 'ovpn' на tun1"
