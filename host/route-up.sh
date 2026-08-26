#!/bin/bash
# Маршруты на macOS: корп-подсети -> в гостя. Уровень 3, доступ по реальным IP.
# Можно запускать как обычным юзером (сам поднимет sudo на нужных шагах),
# так и через sudo -- limactl в обоих случаях зовётся от реального юзера,
# иначе root не видит VM (инстансы Lima лежат в ~/.lima вызвавшего).
set -euo pipefail
VM="${VM:-vpnbox}"
# Корп-имена живут в нескольких доменах -- список задаётся в .env (CORP_DOMAINS).
# macOS-резолвер матчит по домену, поэтому нужен /etc/resolver на каждый.
CORP_DOMAINS="${CORP_DOMAINS:-${CORP_DOMAIN:-}}"

REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME="$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[[ -n "$REAL_HOME" ]] || REAL_HOME="$HOME"
STATE="$REAL_HOME/.local/state/corpvpn"

if [[ "$(id -un)" == "$REAL_USER" ]]; then
  lima()   { limactl shell "$VM" -- "$@" 2>/dev/null | tr -d '\r'; }
  asuser() { "$@"; }
  SUDO="sudo"
else
  # запущены под sudo -- к VM и к своим файлам обращаемся от реального юзера
  lima()   { sudo -u "$REAL_USER" limactl shell "$VM" -- "$@" 2>/dev/null | tr -d '\r'; }
  asuser() { sudo -u "$REAL_USER" "$@"; }
  SUDO=""
fi

asuser mkdir -p "$STATE"

vm_ip="$(lima sh -c "ip -4 -o addr show dev lima0 | awk '{print \$4}' | cut -d/ -f1")"
[[ -n "$vm_ip" ]] || { echo "у гостя нет адреса на lima0 -- VM $VM запущена?" >&2; exit 1; }

subnets="${CORP_SUBNETS:-}"
if [[ -z "$subnets" ]]; then
  subnets="$(lima ip -4 route show dev tun0 | awk '$1!="default"{print $1}')"
fi
[[ -n "$subnets" ]] || { echo "не нашёл подсетей за tun0 -- туннель поднят?" >&2; exit 1; }

asuser sh -c ": > '$STATE/routes'"
for net in $subnets; do
  # Дефолт не трогаем никогда: иначе ВЕСЬ трафик Mac уйдёт в корп-туннель,
  # а вся затея была ровно в обратном.
  case "$net" in
    default|0.0.0.0/0|0.0.0.0/1|128.0.0.0/1)
      echo "пропускаю $net -- это увело бы весь трафик Mac в VPN"; continue ;;
    192.168.64.*|192.168.5.*)
      echo "пропускаю $net -- перекрыло бы связь с самой VM"; continue ;;
  esac
  if $SUDO route -n add -net "$net" "$vm_ip" >/dev/null 2>&1; then
    asuser sh -c "printf '%s\n' '$net' >> '$STATE/routes'"
    echo "+ $net -> $vm_ip"
  else
    echo "! $net не добавился (уже есть?)"
  fi
done

# Корп-DNS достаём устойчиво: systemd-resolved в госте прячет их за стабом
# 127.0.0.53, а сразу после reconnect линк вообще может быть пуст. Порядок:
# CORP_DNS из .env -> не-loopback nameserver'ы из resolv.conf -> resolvectl ->
# кэш прошлого успешного запуска. Найденное кэшируем в STATE/corp-dns.
vpn_dns="${CORP_DNS:-}"
[[ -n "$vpn_dns" ]] || vpn_dns="$(lima sh -c "awk '/^nameserver/ && \$2 !~ /^127\./ {print \$2}' /etc/resolv.conf")"
[[ -n "$vpn_dns" ]] || vpn_dns="$(lima sh -c "resolvectl status 2>/dev/null | awk '/DNS Servers:/{for(i=3;i<=NF;i++) if(\$i ~ /^[0-9.]+$/ && \$i !~ /^127\./) print \$i}'" | sort -u)"
[[ -n "$vpn_dns" ]] || { [[ -f "$STATE/corp-dns" ]] && vpn_dns="$(cat "$STATE/corp-dns")" && echo "корп-DNS из кэша: $(echo $vpn_dns | tr '\n' ' ')"; }
if [[ -n "$vpn_dns" ]]; then
  asuser sh -c "printf '%s\n' '$(echo $vpn_dns | tr '\n' ' ')' | tr ' ' '\n' | sed '/^$/d' > '$STATE/corp-dns'"
fi
if [[ -n "$vpn_dns" && -n "$CORP_DOMAINS" ]]; then
  $SUDO mkdir -p /etc/resolver
  asuser sh -c ": > '$STATE/resolver'"
  ns_block="$(for ns in $vpn_dns; do printf 'nameserver %s\n' "$ns"; done)"
  for d in $CORP_DOMAINS; do
    printf '%s\n' "$ns_block" | $SUDO tee "/etc/resolver/$d" >/dev/null
    asuser sh -c "printf '%s\n' '$d' >> '$STATE/resolver'"
    echo "+ DNS для *.$d -> $(echo $vpn_dns | tr '\n' ' ')"
  done
else
  echo "! не нашёл корп-DNS в /etc/resolv.conf гостя -- резолвер не настроен"
fi
echo; echo "готово. проверь: corpvpn check  и  route -n get <корп-ip>"
