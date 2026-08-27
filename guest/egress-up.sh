#!/bin/bash
# Весь исходящий трафик гостя -> SOCKS5 на хосте.
# Запускать ДО openconnect: vpnc-script закрепит маршрут до VPN-шлюза
# через существующий default, то есть через туннель в SOCKS.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo -E "$0" "$@"

SOCKS_ADDR="${SOCKS_ADDR:-192.168.64.1:1080}"
TUN="${EGRESS_TUN:-tun-egress}"
PROXY_DNS="${PROXY_DNS:-0}"
STATE=/run/corpvpn
mkdir -p "$STATE"

socks_host="${SOCKS_ADDR%:*}"; socks_port="${SOCKS_ADDR##*:}"
socks_ip="$(getent ahostsv4 "$socks_host" | awk 'NR==1{print $1}')"
[[ -n "$socks_ip" ]] || { echo "не резолвится SOCKS-хост: $socks_host" >&2; exit 1; }

# Проверяем прокси до того, как ломать маршруты.
timeout 5 bash -c "exec 3<>/dev/tcp/$socks_ip/$socks_port" 2>/dev/null \
  || { echo "SOCKS5 $socks_ip:$socks_port недоступен" >&2; exit 1; }
echo "SOCKS5: $socks_ip:$socks_port -- отвечает"

# У гостя Lima ДВА default-маршрута (lima0 и eth0). Сохраняем и убираем оба,
# иначе трафик утечёт по второму мимо прокси.
ip -4 route show default > "$STATE/orig-defaults"
[[ -s "$STATE/orig-defaults" ]] || { echo "нет default-маршрута" >&2; exit 1; }
orig_gw="$(awk 'NR==1{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' "$STATE/orig-defaults")"
orig_dev="$(awk 'NR==1{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' "$STATE/orig-defaults")"
printf '%s\n' "$socks_ip" > "$STATE/socks-ip"

# Обход петли: коннект к самому SOCKS-серверу не должен идти в SOCKS.
# Нужен только если прокси не в напрямую подключённой подсети.
if ip -4 route get "$socks_ip" | head -1 | grep -q ' via '; then
  ip route replace "$socks_ip/32" via "$orig_gw" dev "$orig_dev"
  echo "bypass: $socks_ip/32 via $orig_gw dev $orig_dev"
else
  echo "bypass: не нужен, $socks_ip on-link"
fi

ip link show "$TUN" &>/dev/null || ip tuntap add mode tun dev "$TUN"
ip addr replace 198.18.0.1/15 dev "$TUN"
ip link set "$TUN" up

systemctl stop corpvpn-tun2socks 2>/dev/null || true
systemd-run --unit=corpvpn-tun2socks --collect \
  /usr/local/bin/tun2socks --device "$TUN" --proxy "socks5://$SOCKS_ADDR" --loglevel warn >/dev/null
sleep 1
systemctl is-active --quiet corpvpn-tun2socks \
  || { journalctl -u corpvpn-tun2socks --no-pager -n 20; exit 1; }

# Локальные link-маршруты (в т.ч. до Mac) специфичнее default и остаются,
# поэтому limactl shell / ssh из macOS не рвётся.
while ip -4 route show default | grep -q .; do ip route del default; done
ip route add default dev "$TUN"

# --- инвариант песочницы: наружу только через $TUN -------------------------
# vpnc-script на connect/reconnect закрепляет host-маршрут до VPN-шлюза через
# КАЖДЫЙ не-туннельный путь -- чтобы туннель не заворачивался сам в себя. Если
# он сработал в момент, когда egress был разобран (после сна мака, при heal),
# он закрепит шлюз через lima0/eth0. Такой /32 специфичнее default и переживает
# подъём egress обратно: трафик уходит с реального IP мака, корп-шлюз молча его
# дропает, а снаружи это выглядит как "openconnect вечно висит на POST".
orig_devs="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' "$STATE/orig-defaults" | sort -u)"

for dev in $orig_devs; do
  for dst in $(ip -4 route show dev "$dev" | awk '/ via /&&$1!="default"{print $1}'); do
    if [[ "$dst" == "$socks_ip" || "$dst" == "$socks_ip/32" ]]; then
      continue  # единственный легальный обход -- до самого прокси
    fi
    if ip route del "$dst" dev "$dev" 2>/dev/null; then
      echo "снял утечку мимо прокси: $dst dev $dev"
    fi
  done
done

# Фаервол -- страховка на случай, если дыру пробьют снова: пакет мимо $TUN
# должен отлетать сразу и громко, а не уходить в чёрную дыру на 20 секунд
# ретрансмитов. Режем только исходные девайсы: туннели (tun0/tun1) и локальные
# подсети не трогаем, поэтому ни VPN, ни limactl shell не страдают.
local_nets="$(for d in $orig_devs; do ip -4 route show dev "$d" scope link | awk '$1!="default"{print $1}'; done | sort -u | paste -sd, -)"
guard_devs="$(printf '%s\n' $orig_devs | sed 's/.*/"&"/' | paste -sd, -)"
if [[ -n "$local_nets" && -n "$guard_devs" ]]; then
  nft delete table inet corpvpn_guard 2>/dev/null || true
  nft -f - <<NFT
table inet corpvpn_guard {
  chain output {
    type filter hook output priority 0; policy accept;
    ct state established,related accept
    ip daddr { $local_nets, 224.0.0.0/4, 255.255.255.255 } accept
    oif { $guard_devs } reject with icmpx type admin-prohibited
  }
}
NFT
  echo "guard: наружу мимо $TUN -- reject (devs: $guard_devs)"
fi

if [[ "$PROXY_DNS" == "1" ]]; then
  # DNS уходит в туннель => через SOCKS. Требует UDP ASSOCIATE на прокси.
  [[ -f "$STATE/resolv.conf.bak" ]] || cp -aL /etc/resolv.conf "$STATE/resolv.conf.bak"
  # use-vc = резолвить по TCP. Проверено: UDP ASSOCIATE через SOCKS отваливается
  # (tun2socks: "symmetric NAT ... drop packet"), по TCP DNS ходит нормально.
  printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions use-vc\n' > /etc/resolv.conf
  # иначе sudo тормозит на "unable to resolve host"
  grep -q "$(hostname)" /etc/hosts || echo "127.0.1.1 $(hostname)" >> /etc/hosts
  echo "DNS: через прокси, по TCP"
else
  echo "DNS: напрямую через хост -- утечка мимо прокси. PROXY_DNS=1 чтобы завернуть."
fi

echo "--- default ---"; ip -4 route show default
