#!/bin/bash
# Откат install.sh: гасим LaunchAgents (daemon, watchdog, socks), сносим
# sudoers-правило и root-owned бинарь.
# Lima-VM, keychain и state НЕ трогаем (список -- в конце).
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '   \033[33m!\033[0m %s\n' "$1"; }
die()  { printf '\n\033[31m✗ %s\033[0m\n' "$1"; exit 1; }

[[ "$(uname)" == "Darwin" ]] || die "corpvpn пока только под macOS. Твоя ОС: $(uname)"

say "1/4 LaunchAgents"
if command -v corpvpn >/dev/null 2>&1; then
  corpvpn watchdog off 2>/dev/null || warn "corpvpn watchdog off не сработал (может, и не был включён)"
else
  warn "corpvpn не в PATH -- watchdog off пропускаю"
fi
uid="$(id -u)"
for label in com.corpvpn.daemon com.corpvpn.watchdog com.corpvpn.socks; do
  # выгрузка по gui-домену -- так же, как это делает hostctl.go
  if launchctl bootout "gui/$uid/$label" 2>/dev/null; then
    ok "$label выгружен"
  else
    warn "$label не был загружен"
  fi
  # plist тоже сносим, иначе launchd вернёт агент при следующем логине
  rm -f "$HOME/Library/LaunchAgents/$label.plist"
done

say "2/4 sudoers"
if [[ -f /etc/sudoers.d/corpvpn ]]; then
  sudo rm -f /etc/sudoers.d/corpvpn
  warn "убрал /etc/sudoers.d/corpvpn -- ремонтный путь (sudo без пароля на привилегированные verb-ы) больше НЕ работает"
else
  ok "sudoers-правила не было"
fi

say "3/4 бинарь"
if [[ -e /usr/local/bin/corpvpn || -L /usr/local/bin/corpvpn ]]; then
  sudo rm -f /usr/local/bin/corpvpn
  ok "/usr/local/bin/corpvpn снесён"
else
  ok "/usr/local/bin/corpvpn отсутствует"
fi

say "4/4 оставил как было (НЕ тронуто)"
cat <<LEFT
   Lima-VM:   vpnbox       (удалить: limactl delete -f vpnbox)
   keychain:  сервис proxyprocess-vpn (удалить: corpvpn creds rm)
   state:     ~/.local/state/corpvpn
   логи:      ~/Library/Logs/corpvpn-*.log
   бинарь:    $PWD/dist/corpvpn
LEFT
