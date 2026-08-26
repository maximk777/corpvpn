# corpvpn (proxyprocess)

Cisco AnyConnect в песочнице: VPN-клиент живёт в Linux-VM, весь её исходящий
трафик уходит через SOCKS5 на **РФ-хост** (нужен российский IP, иначе корп-шлюз
не пускает), а корп-хосты открываются с macOS по реальным именам и адресам.

**Только macOS.** Пошаговый онбординг для нового человека — [ONBOARDING.md](ONBOARDING.md).

---

## TL;DR

```sh
# один раз
git clone git@github.com:maximk777/corpvpn.git && cd corpvpn
./install.sh                 # зависимости, сборка, VM, туннель до VPS, проверка

# каждый день
corpvpn up                     # SOCKS -> VPN -> маршруты и DNS + авто-реконнект
corpvpn status                 # к чему подключён
corpvpn down                   # погасить всё
```

`install.sh` спросит твой РФ-VPS (`SOCKS_HOST=root@<IP>` в `.env`), корп-креды и
TOTP. `up` просит только `sudo`-пароль (маршруты). Как достать TOTP из Google/
Microsoft-аутентификаторов — в [ONBOARDING.md](ONBOARDING.md).

## Как это работает

```
  Mac                                   гость (Lima)
  ├─ autossh -D :1081 ─► РФ-VPS          tun2socks ←── default route
  │        (egress с RF IP)                  ↑
  │                                      openconnect → tun0 → корп-сеть
  └─ route 10.x → 192.168.64.5 ──────────────┘   (MASQUERADE)
     /etc/resolver/{corp.example,intranet.example} → корп-DNS
```

- **SOCKS-туннель** — LaunchAgent `com.corpvpn.socks`: держит `autossh -D
  192.168.64.1:1081` до `SOCKS_HOST`. Автостарт, автоперезапуск, переживает сон.
- **`up`** = egress в этот SOCKS + openconnect (аутентификация из keychain через
  pty) + на Mac маршруты корп-подсетей в гостя и `/etc/resolver` на корп-домены +
  **watchdog** (`com.corpvpn.watchdog`, раз в 30с зовёт `corpvpn heal`: если `tun0`
  упал — переподнимает VPN без sudo).
- **`down`** — выключает watchdog, снимает маршруты/DNS, гасит туннель.
- Секреты идут только через pty: их нет ни в argv, ни в env, ни на диске гостя.

## Команды

| Команда            | Что делает |
|--------------------|------------|
| `corpvpn up`         | поднять всё + включить авто-реконнект |
| `corpvpn down`       | погасить всё + выключить авто-реконнект |
| `corpvpn status`     | к чему подключён (VM, egress-IP, шлюз, watchdog) |
| `corpvpn setup`      | (пере)ставить SOCKS-туннель из `.env` |
| `corpvpn connect`    | только egress+VPN, без маршрутов на Mac |
| `corpvpn watchdog on\|off` | авто-реконнект вручную |
| `corpvpn creds set\|check\|rm` | корп-логин/пароль/TOTP в keychain |
| `corpvpn code`       | текущий TOTP-код |

## Конфиг (`.env`)

Не в git. Шаблон — `.env.example`.

| Переменная     | Смысл                                        | Дефолт |
|----------------|----------------------------------------------|--------|
| `SOCKS_HOST`   | ssh-таргет РФ-VPS (`root@IP`)               | —      |
| `SOCKS_ADDR`   | SOCKS глазами гостя                          | `192.168.64.1:1081` |
| `VPN_GATEWAY`  | шлюз (`vpn`/`vpn2`/`vpn3.corp.example:8443`)   | `vpn.corp.example:8443` |
| `CORP_DOMAINS` | домены для `/etc/resolver`                   | `corp.example intranet.example` |
| `CORP_DNS`     | корп-DNS вручную, если авто не определился   | (авто) |
| `PROXY_DNS`    | `1` = DNS гостя тоже через прокси            | `1`    |

Шлюзов три — если один не отвечает, поменяй `VPN_GATEWAY`.

## Проверка

```sh
limactl shell vpnbox -- curl -sS -o /dev/null -w '%{http_code}\n' https://wiki.corp.example/   # из гостя
curl -sS -o /dev/null -w '%{http_code} %{remote_ip}\n' https://wiki.corp.example/              # с Mac после up
```
⚠️ `/etc/resolver` на macOS уважают `curl` и браузер, но **не** `dig`/`nslookup` —
они бьют напрямую и покажут «не резолвится». Проверяй `curl`'ом.

## Почему так, а не проще

На macOS нет per-app сетевой изоляции. Проверено и не работает: `proxychains`/
`DYLD_INSERT_LIBRARIES` (vpnagentd под hardened runtime + SIP), `sandbox-exec`
(запрет есть, редиректа нет), `pf` по uid (vpnagentd обязан быть root), свой
`NETransparentProxyProvider` (нужен entitlement Apple, конфликт с сокет-фильтром
Cisco), Docker Desktop (контейнерные адреса с Mac не маршрутизируются). Отсюда
Lima с `vmType: vz` + `vzNAT`: гостю даётся IP, видимый с хоста.

## Установленные факты

- **UDP через SOCKS5 не ходит**: `tun2socks` дропает ответы (symmetric NAT).
  Отсюда DNS по TCP (`options use-vc`) и openconnect с `--no-dtls`.
- Шлюзы `vpn/vpn2/vpn3.corp.example:8443` через прокси отвечают `200`.
- После reconnect гость уходит на split-DNS systemd-resolved и корп-имена вне
  `corp.example` в госте перестают резолвиться. На Mac это не мешает: `/etc/resolver`
  бьёт прямо в корп-DNS (`route-up` кэширует его в `~/.local/state/proxyprocess`).
- TOTP проверен против RFC 6238 (SHA1/256/512); `otpauth-migration://` (Google
  Authenticator) — round-trip. `go test ./...`.

## Разработка

Коллегам Go не нужен: в репозитории лежит готовый **universal-бинарь**
`dist/corpvpn` (Intel + Apple Silicon), `install.sh` его и ставит. После правок
кода пересобери и закоммить бинарь:

```sh
./build-release.sh      # -> dist/corpvpn (arm64+amd64 через lipo)
go build -o bin/corpvpn . # обычная dev-сборка под свою арку
go test ./...
```

Сборка герметична (`unset GOROOT`), чтобы экспортированный в профиле `GOROOT`
не ломал её. `go.mod` требует go 1.25 (из-за `x/term`).

## Безопасность

Пароль и TOTP-seed лежат в одном login keychain — осознанный размен ради
однокомандного коннекта: кто получил разблокированный Mac, получил оба фактора.
`corpvpn creds rm` удаляет. `.env` с адресом РФ-VPS в git не коммитится.
