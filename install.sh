#!/bin/bash
# Однокомандная установка corpvpn на macOS. Идемпотентно -- можно гонять повторно.
# Go НЕ нужен: используем готовый dist/corpvpn. Твоё окружение не трогаем
# (профиль/GOROOT/системный Go не меняем), только ставим lima+autossh (нужны схеме).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$PWD"
BIN="$REPO/dist/corpvpn"

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$1"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$1"; exit 1; }

[[ "$(uname)" == "Darwin" ]] || die "corpvpn пока только под macOS. Твоя ОС: $(uname)"
[[ -f "$BIN" ]] || die "нет $BIN -- обнови репозиторий (git pull). Бинарь должен лежать в dist/"

say "1/7 бинарь corpvpn в PATH"
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true   # снять карантин, если вдруг есть
sudo rm -f /usr/local/bin/wbvpn 2>/dev/null || true        # снести симлинк прежнего имени
sudo ln -sf "$BIN" /usr/local/bin/corpvpn
arch="$(uname -m)"; ok "corpvpn -> $(command -v corpvpn) (арка $arch)"
corpvpn >/dev/null 2>&1 || true   # прогреть/проверить, что бинарь запускается на этой машине
"$BIN" 2>&1 | head -1 >/dev/null && ok "бинарь запускается"

say "2/7 Homebrew + зависимости (lima, autossh)"
if ! command -v brew >/dev/null; then
  warn "нет Homebrew -- ставлю (спросит пароль)"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv)"
for pkg in lima autossh; do
  if brew list --formula "$pkg" >/dev/null 2>&1; then ok "$pkg"; else warn "ставлю $pkg"; brew install "$pkg"; fi
done

say "3/7 .env (твой РФ-VPS)"
if [[ ! -f .env ]]; then cp .env.example .env; warn "создал .env из шаблона"; fi
socks_host="$(grep -E '^SOCKS_HOST=' .env | cut -d= -f2-)"
if [[ -z "$socks_host" || "$socks_host" == "root@YOUR_VPS_IP" ]]; then
  warn "впиши свой РФ-хост: строка SOCKS_HOST=root@<IP твоего VPS>"
  "${EDITOR:-nano}" .env
  socks_host="$(grep -E '^SOCKS_HOST=' .env | cut -d= -f2-)"
fi
[[ -n "$socks_host" ]] || die "SOCKS_HOST не задан в .env"
ok "SOCKS_HOST=$socks_host"

say "4/7 ssh до РФ-хоста без пароля"
if ssh -o BatchMode=yes -o ConnectTimeout=8 "$socks_host" true 2>/dev/null; then
  ok "ssh $socks_host по ключу работает"
else
  warn "добавляю ключ (введи пароль от VPS один раз)"
  ssh-copy-id "$socks_host" || die "не удалось настроить беспарольный ssh до $socks_host"
fi

say "5/7 Lima-VM vpnbox"
# Маунт репозитория в гостя делаем по РЕАЛЬНОМУ пути (в yaml -- плейсхолдер __REPO__).
GENYAML="$REPO/lima/.vpnbox.generated.yaml"
sed "s#__REPO__#$REPO#" lima/vpnbox.yaml > "$GENYAML"
if limactl list vpnbox >/dev/null 2>&1 && limactl shell vpnbox -- test -f /opt/corpvpn/install.sh 2>/dev/null; then
  limactl list vpnbox --format '{{.Status}}' | grep -q Running || limactl start vpnbox --tty=false
  ok "VM на месте (репозиторий смонтирован в /opt/corpvpn)"
else
  if limactl list vpnbox >/dev/null 2>&1; then
    warn "VM смонтирована на старый путь -- пересоздаю (пара минут)"
    limactl stop vpnbox 2>/dev/null || true
    limactl delete vpnbox 2>/dev/null || true
  else
    warn "создаю VM (пара минут)"
  fi
  limactl start "$GENYAML" --name=vpnbox --tty=false
fi

say "6/7 SOCKS-туннель + проверка egress"
corpvpn setup
sleep 3
egress="$(curl -sS --max-time 15 --socks5-hostname 192.168.64.1:1081 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$egress" ]] || die "SOCKS не отвечает -- проверь ssh до $socks_host и ~/Library/Logs/corpvpn-*.log"
ok "egress через РФ-хост, внешний IP: $egress"
gw="$(grep -E "^VPN_GATEWAYS?=" .env | head -1 | cut -d= -f2- | awk "{print \$1}")"
code="$(curl -sS --max-time 20 --socks5-hostname 192.168.64.1:1081 -o /dev/null -w '%{http_code}' "https://$gw/" 2>/dev/null || true)"
[[ "$code" =~ ^(200|301|302|401|403)$ ]] && ok "корп-шлюз $gw отвечает ($code)" || warn "шлюз $gw дал '$code' -- попробуй vpn2/vpn3 в .env"

say "7/7 креды"
if corpvpn creds check >/dev/null 2>&1; then
  ok "логин/пароль/TOTP уже в keychain"
else
  warn "клади креды (TOTP: как достать -- см. ONBOARDING.md)"
  corpvpn creds set
fi

cat <<'DONE'

────────────────────────────────────────────────
Готово. Дальше каждый день:

  corpvpn up        # поднять всё (спросит sudo-пароль для маршрутов)
  corpvpn status    # к чему подключён
  corpvpn down      # погасить всё

Проверка после up:  corpvpn check
────────────────────────────────────────────────
DONE
