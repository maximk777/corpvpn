package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

const usage = `corpvpn -- корп-VPN в песочнице, egress через РФ-хост

Каждый день:
  up               поднять ВСЁ: SOCKS -> VPN -> маршруты и DNS + watchdog
  down             погасить всё и выключить авто-реконнект
  status           к чему сейчас подключён (и подключён ли)
  check            проверить доступность корп-хостов (из CHECK_HOSTS)

Шлюзы:
  gw               показать список VPN-шлюзов и текущий
  gw <номер|хост>  переключиться на другой шлюз (и переподнять, если поднят)

Разово (обычно за тебя делает ./install.sh):
  setup            поставить autossh-туннель до РФ-хоста (из .env)
  creds set        положить логин, пароль и TOTP-seed в login keychain

Прочее:
  creds check      проверить креды и показать текущий код
  creds rm         удалить креды из keychain
  code             напечатать текущий TOTP-код
  connect          только egress+VPN, без маршрутов на Mac
  watchdog on|off  включить/выключить авто-реконнект вручную

Конфиг -- .env в корне репо (см. .env.example). Все корп-адреса только там.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	if runtime.GOOS != "darwin" {
		fmt.Fprintf(os.Stderr, "corpvpn пока докручен только под macOS. Под вашу ОС (%s) поддержки ещё нет.\n", runtime.GOOS)
		os.Exit(1)
	}
	loadDotEnv()
	var err error
	switch os.Args[1] {
	case "creds":
		err = cmdCreds(os.Args[2:])
	case "code":
		err = cmdCode()
	case "setup":
		err = installSocksAgent()
	case "up":
		err = cmdUp()
	case "connect":
		err = connectVPN(false)
	case "heal":
		err = cmdHeal()
	case "watchdog":
		err = cmdWatchdog(os.Args[2:])
	case "gw", "gateway":
		err = cmdGateway(os.Args[2:])
	case "check":
		err = cmdCheck()
	case "status":
		err = cmdStatus()
	case "down":
		err = cmdDown()
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func prompt(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line), err
}

func promptSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(b)), err
}

func cmdCreds(args []string) error {
	sub := "set"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "set":
		user, err := prompt("логин")
		if err != nil {
			return err
		}
		pass, err := promptSecret("пароль")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "TOTP: вставь одно из:")
		fmt.Fprintln(os.Stderr, "  - otpauth://... (Passwords.app: File -> Export, в CSV колонка otpauth)")
		fmt.Fprintln(os.Stderr, "  - otpauth-migration://... (Google Authenticator: Перенос аккаунтов -> QR)")
		fmt.Fprintln(os.Stderr, "  - голый base32-секрет")
		seed, err := promptSecret("totp")
		if err != nil {
			return err
		}
		cfg, err := parseTOTP(seed)
		if err != nil {
			return fmt.Errorf("seed не принят: %w", err)
		}
		if strings.HasPrefix(strings.ToLower(seed), "otpauth-migration://") {
			if _, label, e := parseOtpauthMigration(seed); e == nil && label != "" {
				fmt.Fprintf(os.Stderr, "распознан аккаунт: %s\n", label)
			}
		}
		if user != "" {
			if err := credSet(acctUsername, user); err != nil {
				return err
			}
		}
		if err := credSet(acctPassword, pass); err != nil {
			return err
		}
		if err := credSet(acctTOTP, seed); err != nil {
			return err
		}
		fmt.Printf("сохранено. текущий код: %s (годен %d с)\n",
			cfg.codeAt(time.Now()), cfg.validFor(time.Now()))
		return nil

	case "check":
		for _, a := range []string{acctUsername, acctPassword, acctTOTP} {
			mark := "нет"
			if credExists(a) {
				mark = "есть"
			}
			fmt.Printf("%-14s %s\n", a, mark)
		}
		return cmdCode()

	case "rm":
		for _, a := range []string{acctUsername, acctPassword, acctTOTP} {
			if err := credDelete(a); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", a, err)
			}
		}
		fmt.Println("удалено")
		return nil
	}
	return fmt.Errorf("не знаю подкоманду %q", sub)
}

func cmdCode() error {
	seed, err := credGet(acctTOTP)
	if err != nil {
		return err
	}
	cfg, err := parseTOTP(seed)
	if err != nil {
		return err
	}
	now := time.Now()
	fmt.Printf("%s  (годен ещё %d с)\n", cfg.codeAt(now), cfg.validFor(now))
	return nil
}

// configuredGateways -- шлюзы из .env: VPN_GATEWAYS (список) или VPN_GATEWAY.
// Дефолта нет намеренно -- в репозитории корп-адресов не держим.
func configuredGateways() []string {
	if v := strings.TrimSpace(os.Getenv("VPN_GATEWAYS")); v != "" {
		return strings.Fields(v)
	}
	if v := strings.TrimSpace(os.Getenv("VPN_GATEWAY")); v != "" {
		return []string{v}
	}
	return nil
}

// gatewayCandidates -- порядок перебора: сохранённый через `gw` выбор первым,
// затем остальные из .env.
func gatewayCandidates() []string {
	cands := configuredGateways()
	pref := readGatewayPref()
	if pref == "" {
		return cands
	}
	out := []string{pref}
	for _, g := range cands {
		if g != pref {
			out = append(out, g)
		}
	}
	return out
}

// pickGateway возвращает первый шлюз, ответивший через прокси. Два прохода по
// списку с паузой -- чтобы пережить переподключение туннеля гостя после setup.
func pickGateway(cands []string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		for _, gw := range cands {
			_, err := guest("sh", "-c",
				fmt.Sprintf("curl -sS --max-time 12 -o /dev/null https://%s/", gw))
			if err == nil {
				if gw != cands[0] {
					fmt.Fprintf(os.Stderr, "шлюз %s не ответил, иду на %s\n", cands[0], gw)
				}
				return gw, nil
			}
		}
		time.Sleep(3 * time.Second)
	}
	return "", fmt.Errorf("ни один шлюз не ответил через прокси: %s", strings.Join(cands, ", "))
}

// connectVPN поднимает egress через РФ-SOCKS и корп-VPN. Если alsoRoute --
// сразу настраивает маршруты и DNS на Mac (это и есть `up`, одна кнопка).
func connectVPN(alsoRoute bool) error {
	socks := env("SOCKS_ADDR", "192.168.64.1:1081")
	proxyDNS := env("PROXY_DNS", "1") == "1"

	pass, err := credGet(acctPassword)
	if err != nil {
		return err
	}
	seed, err := credGet(acctTOTP)
	if err != nil {
		return err
	}
	cfg, err := parseTOTP(seed)
	if err != nil {
		return err
	}
	user, _ := credGet(acctUsername)

	if err := ensureVM(); err != nil {
		return err
	}
	if err := ensureEgress(socks, proxyDNS); err != nil {
		return fmt.Errorf("egress не поднялся: %w", err)
	}
	// Проверка до аутентификации: если шлюз не виден, дело не в пароле. С ретраями
	// (после переустановки SOCKS туннель гостя переподцепляется пару секунд) и
	// авто-фолбэком vpn -> vpn2 -> vpn3.
	cands := gatewayCandidates()
	if len(cands) == 0 {
		return fmt.Errorf("не задан VPN-шлюз -- пропиши VPN_GATEWAYS (или VPN_GATEWAY) в .env")
	}
	gateway, err := pickGateway(cands)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "подключаюсь к %s...\n", gateway)
	if err := startTmuxSession(gateway, user, true); err != nil {
		return err
	}
	agent := &authAgent{username: user, password: pass, totp: cfg}
	if err := runAuth(agent, 3*time.Minute); err != nil {
		return err
	}
	if !ifaceUp(vpnTun) {
		return fmt.Errorf("аутентификация прошла, но %s не поднялся -- `limactl shell %s -- sudo tmux attach -t %s`",
			vpnTun, vmName, tmuxName)
	}

	if err := guestPassthrough("sudo", guestDir+"/guest/expose-up.sh"); err != nil {
		return fmt.Errorf("не настроить форвардинг в госте: %w", err)
	}
	nets, err := vpnSubnets()
	if err != nil {
		return err
	}
	ip, err := vmIP()
	if err != nil {
		return err
	}
	fmt.Printf("\nтуннель поднят. подсети за ним: %d\n", len(nets))
	_ = ip
	notify("✅ подключено к " + gateway)

	if alsoRoute {
		fmt.Fprintln(os.Stderr, "\nнастраиваю маршруты и DNS на Mac...")
		if err := hostRouteUp(); err != nil {
			return fmt.Errorf("маршруты на Mac не поднялись: %w", err)
		}
		fmt.Println("\nготово. корп-хосты открываются с Mac по имени. Проверка: corpvpn check")
		return nil
	}
	fmt.Printf("\nчтобы эти адреса открылись с Mac напрямую:\n  ./host/route-up.sh\n")
	return nil
}

// cmdGateway показывает список VPN-шлюзов или переключает текущий.
func cmdGateway(args []string) error {
	cands := configuredGateways()
	if len(cands) == 0 {
		return fmt.Errorf("в .env нет VPN_GATEWAYS/VPN_GATEWAY")
	}
	pref := readGatewayPref()
	if len(args) == 0 {
		for i, g := range cands {
			cur := ""
			if g == pref || (pref == "" && i == 0) {
				cur = "  <- текущий"
			}
			fmt.Printf("  %d) %s%s\n", i+1, g, cur)
		}
		fmt.Println("переключить: corpvpn gw <номер|подстрока хоста>")
		return nil
	}
	sel := args[0]
	chosen := ""
	if n, e := strconv.Atoi(sel); e == nil && n >= 1 && n <= len(cands) {
		chosen = cands[n-1]
	} else {
		for _, g := range cands {
			if strings.Contains(g, sel) {
				chosen = g
				break
			}
		}
	}
	if chosen == "" {
		return fmt.Errorf("не нашёл шлюз %q среди: %s", sel, strings.Join(cands, " "))
	}
	if err := writeGatewayPref(chosen); err != nil {
		return err
	}
	fmt.Printf("шлюз переключён на %s\n", chosen)
	if vmRunning() && ifaceUp(vpnTun) {
		fmt.Fprintln(os.Stderr, "переподключаю VPN на новый шлюз...")
		return connectVPN(true)
	}
	fmt.Println("применится при следующем corpvpn up")
	return nil
}

// cmdCheck проверяет доступность корп-хостов из CHECK_HOSTS (через VPN, из гостя).
func cmdCheck() error {
	hosts := strings.Fields(os.Getenv("CHECK_HOSTS"))
	if len(hosts) == 0 {
		fmt.Println("CHECK_HOSTS не задан в .env -- нечего проверять")
		return nil
	}
	if !vmRunning() || !ifaceUp(vpnTun) {
		return fmt.Errorf("VPN не поднят -- сначала corpvpn up")
	}
	for _, h := range hosts {
		url := h
		if !strings.Contains(h, "://") {
			url = "https://" + h + "/"
		}
		out, err := guest("sh", "-c",
			fmt.Sprintf("curl -sS --max-time 12 -o /dev/null -w '%%{http_code} %%{remote_ip}' %s", url))
		if err != nil {
			fmt.Printf("  ✗ %-28s %v\n", h, err)
		} else {
			fmt.Printf("  ✓ %-28s %s\n", h, out)
		}
	}
	return nil
}

func cmdStatus() error {
	mark := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}

	if !vmRunning() {
		fmt.Println("VM:        ✗ не запущена -- всё выключено")
		fmt.Printf("SOCKS:     %s autossh-агент %s\n", mark(agentIsLoaded(socksAgentLabel)), loadedWord(agentIsLoaded(socksAgentLabel)))
		return nil
	}
	fmt.Println("VM:        ✓ running")

	socksLoaded := agentIsLoaded(socksAgentLabel)
	egressUp := ifaceUp(egressTun)
	ip := guestExternalIP()
	if egressUp {
		fmt.Printf("SOCKS:     %s egress через прокси, внешний IP: %s\n", mark(ip != ""), orDash(ip))
	} else {
		fmt.Printf("SOCKS:     ✗ egress напрямую (не через прокси), внешний IP: %s\n", orDash(ip))
	}
	fmt.Printf("туннель:   %s autossh-агент %s\n", mark(socksLoaded), loadedWord(socksLoaded))

	if ifaceUp(vpnTun) {
		gw := openconnectGateway()
		addr, _ := guest("sh", "-c", "ip -4 -o addr show tun0 | awk '{print $4}'")
		nets, _ := vpnSubnets()
		fmt.Printf("VPN:       ✓ подключён к %s (адрес %s, подсетей %d)\n", orDash(gw), orDash(addr), len(nets))
	} else {
		fmt.Println("VPN:       ✗ не подключён")
	}

	fmt.Printf("watchdog:  %s %s\n", mark(agentIsLoaded(watchdogAgentLabel)), loadedWord(agentIsLoaded(watchdogAgentLabel)))
	return nil
}

func loadedWord(ok bool) string {
	if ok {
		return "включён"
	}
	return "выключен"
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return strings.TrimSpace(s)
}

// guestExternalIP -- реальный внешний IP гостя (через его default -> SOCKS -> РФ-хост).
func guestExternalIP() string {
	out, err := guest("sh", "-c", "curl -sS --max-time 8 https://api.ipify.org")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// openconnectGateway -- к какому шлюзу висит openconnect (последний аргумент в его cmdline).
func openconnectGateway() string {
	out, err := guest("sh", "-c", "ps aux | grep '[o]penconnect' | head -1 | awk '{print $NF}'")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func cmdUp() error {
	if err := connectVPN(true); err != nil {
		return err
	}
	if err := installWatchdogAgent(); err != nil {
		fmt.Fprintf(os.Stderr, "watchdog не встал: %v (VPN поднят, просто без авто-реконнекта)\n", err)
	} else {
		fmt.Println("watchdog включён: если VPN упадёт -- поднимет сам. Остановить всё: corpvpn down")
	}
	return nil
}

// cmdHeal -- то, что раз в 30с дёргает watchdog. Молча выходит, если всё живо
// или если VM намеренно погашена; иначе переподнимает VPN (без маршрутов, sudo не нужно).
func cmdHeal() error {
	if !vmRunning() || !ifaceUp(egressTun) {
		return nil
	}
	if ifaceUp(vpnTun) {
		return nil
	}
	fmt.Fprintln(os.Stderr, "[heal] tun0 упал -- переподнимаю VPN")
	notify("🖕 VPN отвалился — переподключаюсь…")
	return connectVPN(false)
}

func cmdWatchdog(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "on":
		if err := installWatchdogAgent(); err != nil {
			return err
		}
		fmt.Println("watchdog включён")
		return nil
	case "off":
		removeWatchdogAgent()
		fmt.Println("watchdog выключен")
		return nil
	case "", "status":
		if agentIsLoaded(watchdogAgentLabel) {
			fmt.Println("watchdog: включён")
		} else {
			fmt.Println("watchdog: выключен")
		}
		return nil
	}
	return fmt.Errorf("watchdog on|off|status")
}

func cmdDown() error {
	removeWatchdogAgent() // чтобы не воскрешал специально погашенный туннель
	// Сначала снимаем маршруты и DNS на Mac -- это надо сделать даже если VM уже нет.
	if err := hostRouteDown(); err != nil {
		fmt.Fprintf(os.Stderr, "маршруты на Mac снялись с ошибкой: %v\n", err)
	}
	if !vmRunning() {
		fmt.Println("VM не запущена -- на Mac всё снято")
		return nil
	}
	_, _ = guest("sudo", "tmux", "kill-session", "-t", tmuxName)
	if err := guestPassthrough("sudo", guestDir+"/guest/egress-down.sh"); err != nil {
		return err
	}
	fmt.Println("туннель погашен, egress напрямую")
	notify("🖕 VPN отключён")
	return nil
}
