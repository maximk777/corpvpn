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

# Парольless sudo на фиксированный список verb-ов root-owned бинаря
# (/usr/local/bin/corpvpn, не симлинк), чтобы `corpvpn up/down` и daemon
# не спрашивали пароль. Каждая запись пинает точный argv -- wildcard'ов
# нет, лишние аргументы грант не проходят. env_keep пробрасывает
# переменные конфигурации через sudo: sudoers по умолчанию делает
# env_reset и срезает CORPVPN_*/DNS-переменные, которые S5 кладёт в
# окружение root-net-up (см. rootEnviron() в steps_host.go). Новые verb-ы
# берут входные данные из argv, новых переменных окружения не появилось.
install_sudoers() {
  local tmp rule install_user
  rule="/usr/local/bin/corpvpn root-net-up, /usr/local/bin/corpvpn root-net-down"
  rule+=", /usr/local/bin/corpvpn root-arp-flush"
  rule+=", /usr/local/bin/corpvpn root-resolver-kick"
  rule+=", /usr/local/bin/corpvpn root-hosts-up"
  rule+=", /usr/local/bin/corpvpn root-hosts-down"
  rule+=", /usr/local/bin/corpvpn root-dns-fwd up, /usr/local/bin/corpvpn root-dns-fwd down"
  install_user="${USER:-$(id -un)}"
  tmp="$(mktemp)"
  printf 'Defaults env_keep += "CORPVPN_SUBNETS CORPVPN_GATEWAY CORPVPN_STATE_DIR DNS_MODE CORP_DOMAINS OVPN_DOMAINS CORP_DNS BANK_DOMAIN"\n' > "$tmp"
  printf '%s ALL=(root) NOPASSWD: %s\n' "$install_user" "$rule" >> "$tmp"
  if sudo test -f /etc/sudoers.d/corpvpn && sudo cmp -s "$tmp" /etc/sudoers.d/corpvpn; then
    rm -f "$tmp"
    ok "sudoers-правило уже актуально"
    return
  fi
  # Файл делаем root-owned ДО финальной валидации: иначе содержимое можно
  # подменить между visudo и install (TOCTOU против привилегированной установки).
  sudo chown root:wheel "$tmp"
  sudo chmod 0440 "$tmp"
  if ! sudo visudo -cf "$tmp" >/dev/null; then
    sudo rm -f "$tmp"
    die "sudoers-правило не прошло visudo -cf -- привилегии не ставлю"
  fi
  sudo install -m 0440 -o root -g wheel "$tmp" /etc/sudoers.d/corpvpn
  sudo rm -f "$tmp"
  ok "sudo без пароля на привилегированные verb-ы /usr/local/bin/corpvpn (дальше -- headless через sudo -n)"
}

[[ "$(uname)" == "Darwin" ]] || die "corpvpn пока только под macOS. Твоя ОС: $(uname)"
[[ -f "$BIN" ]] || die "нет $BIN -- обнови репозиторий (git pull). Бинарь должен лежать в dist/"

say "1/8 бинарь corpvpn в /usr/local/bin (root-owned копия)"
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true   # снять карантин, если вдруг есть
sudo rm -f /usr/local/bin/wbvpn 2>/dev/null || true        # снести бинарь прежнего имени (если остался)
# Старая схема ставила сюда симлинк в репозиторий: линк сносим ДО cp, иначе
# cp через линк напишет в dist/corpvpn (или упадёт, увидев src==dst).
sudo rm -f /usr/local/bin/corpvpn
sudo cp "$BIN" /usr/local/bin/corpvpn
sudo chown root:wheel /usr/local/bin/corpvpn
sudo chmod 755 /usr/local/bin/corpvpn
install_sudoers
arch="$(uname -m)"; ok "corpvpn -> $(command -v corpvpn) (арка $arch)"
/usr/local/bin/corpvpn >/dev/null 2>&1 || true   # прогреть/проверить, что бинарь запускается на этой машине
"$BIN" 2>&1 | head -1 >/dev/null && ok "бинарь запускается"

say "2/8 LaunchAgents: снос watchdog, установка daemon"
[[ -f "$REPO/com.corpvpn.daemon.plist.example" ]] || die "нет $REPO/com.corpvpn.daemon.plist.example"
uid="$(id -u)"
# Watchdog прежней схемы и daemon друг друга дублируют (оба реконнектят):
# агент выгружаем и удаляем его plist, иначе launchd вернёт его на логине.
launchctl bootout "gui/$uid/com.corpvpn.watchdog" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/com.corpvpn.watchdog.plist"
# Демон -- это желаемое состояние под присмотром launchd: RunAtLoad стартует
# его на логине, KeepAlive перезапускает при падении. На первой установке
# агент ещё не загружен -- kickstart падает, тогда обычный load (RunAtLoad
# стартует сам).
mkdir -p "$HOME/Library/LaunchAgents"
# WorkingDirectory в .example -- плейсхолдер: подставляем корень репозитория
# (install.sh работает из него), иначе launchd стартует daemon с cwd=/ и
# repoRoot() не находит .env -- демон не сходится никогда. __USER_HOME__ --
# то же для stdout/stderr демона (~/Library/Logs/corpvpn-daemon.log).
sed -e "s|__REPO_ROOT__|$REPO|" -e "s|__USER_HOME__|$HOME|" "$REPO/com.corpvpn.daemon.plist.example" > "$HOME/Library/LaunchAgents/com.corpvpn.daemon.plist"
if ! launchctl kickstart -k "gui/$uid/com.corpvpn.daemon" 2>/dev/null; then
  launchctl load "$HOME/Library/LaunchAgents/com.corpvpn.daemon.plist"
fi
ok "daemon-агент установлен (com.corpvpn.daemon, KeepAlive)"

say "3/8 Homebrew + зависимости (lima, autossh)"
if ! command -v brew >/dev/null; then
  warn "нет Homebrew -- ставлю (спросит пароль)"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || /usr/local/bin/brew shellenv)"
for pkg in lima autossh; do
  if brew list --formula "$pkg" >/dev/null 2>&1; then ok "$pkg"; else warn "ставлю $pkg"; brew install "$pkg"; fi
done

say "4/8 .env (твой РФ-VPS)"
if [[ ! -f .env ]]; then cp .env.example .env; warn "создал .env из шаблона"; fi
socks_host="$(grep -E '^SOCKS_HOST=' .env | cut -d= -f2-)"
if [[ -z "$socks_host" || "$socks_host" == "root@YOUR_VPS_IP" ]]; then
  warn "впиши свой РФ-хост: строка SOCKS_HOST=root@<IP твоего VPS>"
  "${EDITOR:-nano}" .env
  socks_host="$(grep -E '^SOCKS_HOST=' .env | cut -d= -f2-)"
fi
[[ -n "$socks_host" ]] || die "SOCKS_HOST не задан в .env"
ok "SOCKS_HOST=$socks_host"

say "5/8 ssh до РФ-хоста без пароля"
if ssh -o BatchMode=yes -o ConnectTimeout=8 "$socks_host" true 2>/dev/null; then
  ok "ssh $socks_host по ключу работает"
else
  warn "добавляю ключ (введи пароль от VPS один раз)"
  ssh-copy-id "$socks_host" || die "не удалось настроить беспарольный ssh до $socks_host"
fi

say "6/8 Lima-VM vpnbox"
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

say "7/8 SOCKS-туннель + проверка egress"
corpvpn setup
sleep 3
egress="$(curl -sS --max-time 15 --socks5-hostname 192.168.64.1:1081 https://api.ipify.org 2>/dev/null || true)"
[[ -n "$egress" ]] || die "SOCKS не отвечает -- проверь ssh до $socks_host и ~/Library/Logs/corpvpn-*.log"
ok "egress через РФ-хост, внешний IP: $egress"
gw="$(grep -E "^VPN_GATEWAYS?=" .env | head -1 | cut -d= -f2- | awk "{print \$1}")"
code="$(curl -sS --max-time 20 --socks5-hostname 192.168.64.1:1081 -o /dev/null -w '%{http_code}' "https://$gw/" 2>/dev/null || true)"
[[ "$code" =~ ^(200|301|302|401|403)$ ]] && ok "корп-шлюз $gw отвечает ($code)" || warn "шлюз $gw дал '$code' -- попробуй vpn2/vpn3 в .env"

say "8/8 креды"
if corpvpn creds check >/dev/null 2>&1; then
  ok "логин/пароль/TOTP уже в keychain"
else
  warn "клади креды (TOTP: как достать -- см. ONBOARDING.md)"
  corpvpn creds set
fi

cat <<'DONE'

────────────────────────────────────────────────
Готово. Дальше каждый день:

  corpvpn up        # поднять всё (sudo для root-net-up уже без пароля)
  corpvpn status    # к чему подключён
  corpvpn down      # погасить всё

Проверка после up:  corpvpn check
────────────────────────────────────────────────
DONE
