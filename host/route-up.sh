#!/bin/bash
# Маршруты на macOS: корп-подсети -> в гостя. Уровень 3, доступ по реальным IP.
# Можно запускать как обычным юзером (сам поднимет sudo на нужных шагах),
# так и через sudo -- limactl в обоих случаях зовётся от реального юзера,
# иначе root не видит VM (инстансы Lima лежат в ~/.lima вызвавшего).
set -euo pipefail
VM="${VM:-vpnbox}"
# CIDR helpers from lib/ (filter_excluded/net_in_prefix) -- for CORP_EXCLUDE_SUBNETS below.
. "$(cd "$(dirname "$0")" && pwd)/lib/netfilter.sh"
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

# sudo нужен для route и /etc/resolver. Спрашиваем пароль ОДИН раз и заранее:
# ниже в цикле stderr sudo заглушён, там приглашение было бы невидимым -- юзер
# просто смотрел бы в молчащий терминал, а скрипт падал бы с голым exit 1.
if [[ -n "$SUDO" ]] && ! sudo -n true 2>/dev/null; then
  echo "нужен sudo -- маршруты и /etc/resolver правятся от root:"
  sudo -v || { echo "без sudo маршруты не поднять" >&2; exit 1; }
fi

asuser mkdir -p "$STATE"

vm_ip="$(lima sh -c "ip -4 -o addr show dev lima0 | awk '{print \$4}' | cut -d/ -f1")"
[[ -n "$vm_ip" ]] || { echo "у гостя нет адреса на lima0 -- VM $VM запущена?" >&2; exit 1; }

subnets="${CORP_SUBNETS:-}"
if [[ -z "$subnets" ]]; then
  # tun0 (Cisco) и, если есть, tun1. `|| true`, чтобы отсутствие tun1 не роняло
  # скрипт (set -e + pipefail: `ip route show dev tun1` без tun1 = не-ноль).
  subnets="$(lima sh -c 'ip -4 route show dev tun0 2>/dev/null; ip -4 route show dev tun1 2>/dev/null; true' | awk '$1!="default"{print $1}' | sort -u)"
fi
[[ -n "$subnets" ]] || { echo "не нашёл подсетей за tun0/tun1 -- туннель поднят?" >&2; exit 1; }

# The exclude filter runs BEFORE the add loop, so a removed prefix reaches
# neither `route -n add` nor the routes state file. Empty/unset
# CORP_EXCLUDE_SUBNETS is a no-op (filter_excluded keeps the whole list).
survivors="$(filter_excluded "${CORP_EXCLUDE_SUBNETS:-}" $subnets)"
removed="$(comm -23 <(printf '%s\n' $subnets | sort -u) <(printf '%s\n' "$survivors" | sort -u))"
for net in $removed; do
  echo "excluded by CORP_EXCLUDE_SUBNETS: $net" >&2
done
subnets="$survivors"

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

# Корп-DNS берём НАСТОЯЩИЙ -- тот, что пушит шлюз (его ловит guest/vpnc-hook.sh
# в /run/corpvpn/vpn-dns). systemd-resolved прячет реальный DNS, а из resolv.conf/
# resolvectl можно случайно схватить локальные шлюзы (192.168.x) -- поэтому их не берём.
# Порядок: CORP_DNS из .env -> перехваченный DNS шлюза -> кэш прошлого запуска.
vpn_dns="${CORP_DNS:-}"
[[ -n "$vpn_dns" ]] || vpn_dns="$(lima sh -c 'awk -F= "/^DNS=/{print \$2}" /run/corpvpn/vpn-dns 2>/dev/null')"
[[ -n "$vpn_dns" ]] || { [[ -f "$STATE/corp-dns" ]] && vpn_dns="$(cat "$STATE/corp-dns")" && echo "корп-DNS из кэша: $(echo $vpn_dns | tr '\n' ' ')"; }
if [[ -n "$vpn_dns" ]]; then
  asuser sh -c "printf '%s\n' '$(echo $vpn_dns | tr '\n' ' ')' | tr ' ' '\n' | sed '/^$/d' > '$STATE/corp-dns'"
fi
if [[ -z "$vpn_dns" ]]; then
  echo "! не определил корп-DNS -- резолвер не настроен"
elif [[ "${DNS_MODE:-primary}" == "primary" ]]; then
  # РЕЖИМ PRIMARY (по умолчанию): корп-DNS -- основной DNS Mac. Он резолвит и
  # корп-имена (10.x), и публичные (проверено), поэтому НИКАКИХ списков доменов
  # не нужно -- резолвится всё само. 1.1.1.1 добавляем как fallback, чтобы при
  # обрыве туннеля не умер весь DNS. `down` вернёт исходные серверы.
  dev="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  svc="$(networksetup -listnetworkserviceorder 2>/dev/null | awk -v d="$dev" '
    /^\([0-9]+\)/{name=$0; sub(/^\([0-9]+\) /,"",name)}
    /Device: /{ if ($0 ~ ("Device: " d ")")) print name }' | head -1)"
  [[ -n "$svc" ]] || svc="Wi-Fi"
  if [[ ! -f "$STATE/dns-primary" ]]; then
    orig="$(networksetup -getdnsservers "$svc" 2>/dev/null | awk '/^[0-9]/{printf "%s ", $0}')"
    asuser sh -c "printf '%s\n%s\n' '$svc' '$orig' > '$STATE/dns-primary'"
  fi
  $SUDO networksetup -setdnsservers "$svc" $vpn_dns 1.1.1.1
  echo "+ основной DNS Mac -> $(echo $vpn_dns | tr '\n' ' ')(+1.1.1.1) на '$svc' -- домены перечислять не нужно"
elif [[ -n "$CORP_DOMAINS" ]]; then
  # РЕЖИМ RESOLVER: per-domain /etc/resolver (не трогает глобальный DNS Mac).
  $SUDO mkdir -p /etc/resolver || { echo "не создать /etc/resolver -- нет прав root" >&2; exit 1; }
  asuser sh -c ": > '$STATE/resolver'"
  ns_block="$(for ns in $vpn_dns; do printf 'nameserver %s\n' "$ns"; done)"
  for d in $CORP_DOMAINS ${OVPN_DOMAINS:-}; do
    printf '%s\n' "$ns_block" | $SUDO tee "/etc/resolver/$d" >/dev/null
    asuser sh -c "printf '%s\n' '$d' >> '$STATE/resolver'"
    echo "+ DNS для *.$d -> $(echo $vpn_dns | tr '\n' ' ')"
  done
else
  echo "! DNS_MODE=resolver, но CORP_DOMAINS пуст -- резолвер не настроен (или включи DNS_MODE=primary)"
fi
echo; echo "готово. проверь: corpvpn check  и  route -n get <корп-ip>"
