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
  │                              openconnect → tun0 → корп-сеть (Cisco)
  │                              openvpn     → tun1 → доп-сеть (опц.)
  └─ route 10.x → 192.168.64.5 ──────────────┘   (MASQUERADE обоих tun)
     /etc/resolver/<корп-домены> → корп-DNS (тот, что реально пушит шлюз)
```

- **SOCKS-туннель** — LaunchAgent `com.corpvpn.socks`: держит `autossh -D
  192.168.64.1:1081` до `SOCKS_HOST`. Автостарт, автоперезапуск, переживает сон.
- **`up`** = egress в SOCKS → **Cisco** (openconnect, tun0; аутентификация из
  keychain через pty, авто-фолбэк `vpn`→`vpn2`→`vpn3`) → **OpenVPN** рядом (tun1,
  если задан `OVPN_CONFIG`) → на Mac маршруты подсетей **обоих** туннелей в гостя и
  `/etc/resolver` на корп-домены → **watchdog** (`com.corpvpn.watchdog`, раз в 30с
  `corpvpn heal`: если `tun0` упал — переподнимает без sudo).
- **Корп-DNS берётся правильный**: `guest/vpnc-hook.sh` перехватывает то, что
  реально пушит шлюз (`INTERNAL_IP4_DNS`), — не полагаемся на systemd-resolved,
  который его прячет. Меняется шлюз — меняется DNS, всё подхватывается само.
- **Два VPN на разных интерфейсах** (tun0/tun1) не конфликтуют: `10.0.0.0/8` остаётся
  у OpenVPN (им ловятся WB-only 10.x), фильтруются только `redirect-gateway` и
  `dhcp-option`; чужие префиксы убирает `CORP_EXCLUDE_SUBNETS` в `.env`.
- **`down`** — выключает watchdog, гасит оба VPN, снимает маршруты/DNS.
- **Уведомления** macOS о смене состояния (✅ подключено / 🖕 отвалился/отключён),
  выключаются `NOTIFY=0`.
- Секреты идут только через pty: их нет ни в argv, ни в env, ни на диске гостя.

## Команды

| Команда            | Что делает |
|--------------------|------------|
| `corpvpn up`         | поднять всё (Cisco + OpenVPN + маршруты) + авто-реконнект |
| `corpvpn down`       | погасить всё + выключить авто-реконнект |
| `corpvpn status`     | к чему подключён (VM, egress-IP, шлюз, OpenVPN, watchdog) |
| `corpvpn check`      | проверить доступность корп-хостов из `CHECK_HOSTS` (с Mac) |
| `corpvpn gw [n\|хост]` | список VPN-шлюзов / переключиться на другой |
| `corpvpn setup`      | (пере)ставить SOCKS-туннель из `.env` |
| `corpvpn connect`    | только egress+Cisco, без маршрутов на Mac |
| `corpvpn watchdog on\|off` | авто-реконнект вручную |
| `corpvpn creds set\|ovpn\|check\|rm` | логин/пароль/TOTP (+ passphrase ключа OpenVPN) в keychain |
| `corpvpn code`       | текущий TOTP-код |

## Конфиг (`.env`)

Не в git. Шаблон — `.env.example`.

| Переменная      | Смысл                                        | Дефолт |
|-----------------|----------------------------------------------|--------|
| `SOCKS_HOST`    | ssh-таргет РФ-VPS (`root@IP`)                | —      |
| `SOCKS_ADDR`    | SOCKS глазами гостя                          | `192.168.64.1:1081` |
| `VPN_GATEWAYS`  | список Cisco-шлюзов через пробел (берётся первый живой; свитч — `corpvpn gw`) | — |
| `CORP_DOMAINS`  | домены для `/etc/resolver`                   | — |
| `CHECK_HOSTS`   | хосты для `corpvpn check`                    | — |
| `CORP_EXCLUDE_SUBNETS` | префиксы чужих VPN-клиентов (напр. GitLab на мак-OpenVPN) — corpvpn их не ставит на Mac | — |
| `OVPN_CONFIG`   | путь к `.ovpn` для OpenVPN в песочнице (пусто = не поднимать) | — |
| `CORP_DNS`      | корп-DNS вручную (обычно ловится сам)        | (авто) |
| `PROXY_DNS`     | `1` = DNS гостя тоже через прокси            | `1`    |
| `NOTIFY`        | `0` = выключить macOS-уведомления            | `1`    |

Корп-адреса (шлюзы, домены, хосты, путь к `.ovpn`) держатся **только в `.env`** —
в репозитории их нет. Смена шлюза: `corpvpn gw 2` (или подстрокой хоста).

## Второй VPN (OpenVPN) в той же песочнице

Если помимо Cisco нужен ещё OpenVPN (доступ к сети, которую Cisco не покрывает):

```sh
# в .env:
OVPN_CONFIG=/путь/к/твоему.ovpn
corpvpn creds ovpn      # passphrase на приватный ключ .ovpn (если ключ зашифрован)
corpvpn down && corpvpn up
```

`up` поднимет его на `tun1` рядом с Cisco (`tun0`): конфиг копируется в гостевой
tmpfs на время сессии, passphrase вводится через pty (на диск не пишется), до
сервера идём напрямую (bypass мимо SOCKS — РФ-IP ему не нужен). Маршруты обоих
туннелей уезжают на Mac. Свой мак-OpenVPN **оставь**: он обслуживает GitLab, а
пересекающиеся с ним префиксы corpvpn исключит через `CORP_EXCLUDE_SUBNETS`.

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
  Отсюда DNS по TCP (`options use-vc`) и openconnect/openvpn по TCP (`--no-dtls`).
- **Корп-DNS у разных шлюзов разный** и systemd-resolved его прячет (в госте стаб
  `127.0.0.53`, tun0 в resolvectl пуст). Поэтому берём его из `INTERNAL_IP4_DNS`
  через обёртку `guest/vpnc-hook.sh` — надёжнее любого пост-фактум определения.
  На Mac это не зависит от гостевого DNS: `/etc/resolver` бьёт прямо в корп-DNS.
- **Wildberries-OpenVPN пушит `10.0.0.0/8`** — маршрут оставляем: WB-only 10.x
  (напр. стейдж) ловятся именно этим /8 на tun1. В `--pull-filter` уходят только
  `redirect-gateway` и `dhcp-option` (`guest/ovpn-up.sh`).
- **GitLab (`gitlab.wildberries.ru`) живёт на отдельном мак-OpenVPN**, не на corpvpn:
  выключать его не надо — пересекающиеся префиксы чужих клиентов вносятся в
  `CORP_EXCLUDE_SUBNETS` в `.env`, и corpvpn их на Mac не ставит.
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
