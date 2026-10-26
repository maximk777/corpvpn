package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"corpvpn/internal/authstate"
	"corpvpn/internal/daemon"
	"corpvpn/internal/failure"
	"corpvpn/internal/hostops"
	"corpvpn/internal/netutil"
	"corpvpn/internal/probe"
	"corpvpn/internal/verbs"
	"golang.org/x/term"
)

// State-dir file names shared by the CLI and the daemon: desired.json is
// the CLI->daemon intent channel, status.json is the daemon->CLI view.
const (
	desiredFile = "desired.json"
	statusFile  = "status.json"
	hostsFile   = "/etc/hosts"
	dnsFwdPid   = "dnsfwd.pid"
	// daemonLabel is the LaunchAgent label of the desired-state daemon.
	daemonLabel = "com.corpvpn.daemon"
)

const usage = `corpvpn -- корп-VPN в песочнице, egress через РФ-хост

Каждый день:
  up               поднять ВСЁ: SOCKS -> VPN -> маршруты и DNS (демон дальше держит конвергенцию)
  down             погасить всё и выключить авто-реконнект
  status           к чему сейчас подключён (и подключён ли)
  check            проверить доступность корп-хоста (BANK_PROBE_HOST)

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
  heal             один проход реконсиляции прямо сейчас

Конфиг -- .env в корне репо (см. .env.example). Все корп-адреса только там.
`

// errUsage marks an unknown command: main prints the usage and exits 2.
var errUsage = errors.New("usage")

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
	if err := dispatch(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Print(usage)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

// dispatch routes one command; extra arguments ride in args[1:]. The root
// verbs mirror the sudoers grant written by install.sh, so their argv is
// fixed and validated on both sides.
func dispatch(args []string) error {
	switch args[0] {
	case "creds":
		return cmdCreds(args[1:])
	case "code":
		return cmdCode()
	case "setup":
		return installSocksAgent()
	case "up":
		return cmdUp()
	case "connect":
		return connectVPN(false)
	case "heal":
		return cmdHeal()
	case "gw", "gateway":
		return cmdGateway(args[1:])
	case "check":
		return cmdCheck()
	case "status":
		return cmdStatus()
	case "down":
		return cmdDown()
	case "daemon":
		return cmdDaemon()
	case "root-net-up":
		return cmdRootNetUp()
	case "root-net-down":
		return cmdRootNetDown()
	case "root-arp-flush":
		return verbFlushClonedRoutes(env("VM_IFACE", "bridge100"))
	case "root-resolver-kick":
		return verbResolverKick()
	case "root-hosts-up":
		return verbHostsUp(cachedHostsEntries(stateDir()))
	case "root-hosts-down":
		return verbHostsDown()
	case "root-dns-fwd":
		return cmdRootDNSFwd(args[1:])
	case "dnsfwd-run":
		if len(args) < 3 {
			return fmt.Errorf("dnsfwd-run <bankDomain> <upstream>")
		}
		return verbDNSFwdRun(args[1], args[2])
	default:
		return errUsage
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
		fmt.Fprintln(os.Stderr, "  (можно вставить путь к скриншоту QR-кода — распознаю сам)")
		seed, err := promptSecret("totp")
		if err != nil {
			return err
		}
		// Вставили путь к картинке со скриншотом QR? Распознаём.
		if looksLikeImagePath(seed) {
			fmt.Fprintln(os.Stderr, "распознаю QR из картинки...")
			decoded, e := decodeQRImage(seed)
			if e != nil {
				return fmt.Errorf("не распознать QR: %w", e)
			}
			seed = decoded
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

		// Свежие креды снимают блокировку авторизаций (ADR-005): heal
		// разморозится на следующем тике без ручного up.
		if err := authstate.Reset(stateDir()); err != nil {
			return fmt.Errorf("не сбросить блокировку авторизаций: %w", err)
		}

		// Опционально: passphrase на приватный ключ Wildberries-OpenVPN.
		fmt.Fprintln(os.Stderr, "OpenVPN: пароль на приватный ключ (.ovpn). Enter -- пропустить.")
		ovpnPass, err := promptSecret("ovpn key pass")
		if err != nil {
			return err
		}
		if ovpnPass != "" {
			if err := credSet(acctOVPNKey, ovpnPass); err != nil {
				return err
			}
			fmt.Println("passphrase ключа OpenVPN сохранён")
		}
		return nil

	case "check":
		for _, a := range []string{acctUsername, acctPassword, acctTOTP, acctOVPNKey} {
			mark := "нет"
			if credExists(a) {
				mark = "есть"
			}
			fmt.Printf("%-14s %s\n", a, mark)
		}
		return cmdCode()

	case "ovpn":
		// Только passphrase на ключ OpenVPN -- чтобы не перевводить остальные креды.
		p, err := promptSecret("ovpn key pass")
		if err != nil {
			return err
		}
		if p == "" {
			return fmt.Errorf("пусто -- ничего не сохранил")
		}
		if err := credSet(acctOVPNKey, p); err != nil {
			return err
		}
		fmt.Println("passphrase ключа OpenVPN сохранён")
		return nil

	case "rm":
		for _, a := range []string{acctUsername, acctPassword, acctTOTP, acctOVPNKey} {
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

// connectCisco поднимает egress через РФ-SOCKS и Cisco AnyConnect (tun0).
// Маршруты на Mac и OpenVPN -- отдельными шагами (см. connectVPN/cmdUp).
func connectCisco() error {
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
	fmt.Printf("\nCisco поднят. подсети за tun0: %d\n", len(nets))
	_ = ip
	notify("✅ подключено к " + gateway)
	return nil
}

// connectVPN -- Cisco + (опционально) маршруты на Mac. Для `connect` и свитча шлюза.
func connectVPN(alsoRoute bool) error {
	if err := connectCisco(); err != nil {
		return err
	}
	if alsoRoute {
		fmt.Fprintln(os.Stderr, "\nнастраиваю маршруты и DNS на Mac...")
		if err := hostRouteUp(); err != nil {
			return fmt.Errorf("маршруты на Mac не поднялись: %w", err)
		}
		fmt.Println("\nготово. Проверка: corpvpn check")
		return nil
	}
	fmt.Printf("\nчтобы эти адреса открылись с Mac:\n  corpvpn up   (или ./host/route-up.sh)\n")
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

// cmdCheck проверяет доступность корп-хоста (через VPN, с Mac). Хост берётся
// из контракта конфига банка: BANK_PROBE_HOST, по умолчанию btg.wb-bank.ru;
// CHECK_HOSTS больше не часть контракта.
func cmdCheck() error {
	bc, err := loadBankConfig(os.Getenv)
	if err != nil {
		return err
	}
	if !vmRunning() || !ifaceUp(vpnTun) {
		return fmt.Errorf("VPN не поднят -- сначала corpvpn up")
	}
	h := bc.BankProbeHost
	url := h
	if !strings.Contains(h, "://") {
		url = "https://" + h + "/"
	}
	// С Mac (через /etc/resolver + маршруты в гостя) -- как в браузере.
	out, err := macCurl(url)
	code := strings.Fields(out)
	if err == nil && len(code) > 0 && code[0] != "000" && code[0] != "" {
		fmt.Printf("  ✓ %-28s %s\n", h, out)
	} else {
		fmt.Printf("  ✗ %-28s %s\n", h, orDash(out))
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

	// The daemon owns the status view: make sure its agent exists before
	// reading, then render the file it wrote.
	kickstartDaemon()
	printDaemonStatus()

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

	// OpenVPN (tun1) -- показываем только если реально поднят (обычно нет: SSO-gated).
	if ifaceUp(ovpnTun) {
		addr, _ := guest("sh", "-c", "ip -4 -o addr show tun1 | awk '{print $4}'")
		fmt.Printf("OpenVPN:   ✓ поднят (tun1, адрес %s)\n", orDash(addr))
	}

	fmt.Printf("демон:     %s launchd-агент %s\n", mark(agentIsLoaded(daemonLabel)), loadedWord(agentIsLoaded(daemonLabel)))
	return nil
}

// kickstartDaemon starts the desired-state daemon when its LaunchAgent is
// not loaded. Errors are ignored on purpose: `status` must work without
// the daemon, it just falls back to the "нет статуса" line.
func kickstartDaemon() {
	if agentIsLoaded(daemonLabel) {
		return
	}
	_ = exec.Command("launchctl", "kickstart", "-k", "gui/"+guiUID()+"/"+daemonLabel).Run()
}

// printDaemonStatus renders the daemon-written status file: the desired
// state, per-step actual results, the last probe outcome and the contested
// hosts. A missing or unreadable file means the daemon has not reported
// anything yet.
func printDaemonStatus() {
	st, err := daemon.ReadStatus(filepath.Join(stateDir(), statusFile))
	if err != nil {
		fmt.Println("daemon: нет статуса")
		return
	}
	fmt.Printf("daemon:    желаемый статус: %s\n", orDash(string(st.Desired)))
	names := make([]string, 0, len(st.Steps))
	for name := range st.Steps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("  %-13s %s\n", name+":", st.Steps[name])
	}
	fmt.Printf("  probe:         %s\n", orDash(st.Probe))
	if len(st.Contested) > 0 {
		fmt.Printf("  contested:     %s\n", strings.Join(st.Contested, ", "))
	}
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

// recordDesired persists the user intent in desired.json for the daemon --
// the only CLI->daemon channel. A failed write is a warning, not a command
// failure: the reconcile already ran, the daemon just converges on a later
// tick.
func recordDesired(d daemon.Desired) {
	if err := daemon.WriteDesired(filepath.Join(stateDir(), desiredFile), d); err != nil {
		fmt.Fprintf(os.Stderr, "не записать desired=%s для демона: %v\n", d, err)
	}
}

// recordContested is the producer side of `status`: the daemon core leaves
// Status.Contested nil, so the process that ran the routes (root-net-up)
// records what the pass saw into the daemon status file. Best-effort on
// both read and write; with no status file yet, one is created carrying the
// desired state from desired.json.
func recordContested(contested []string) {
	path := filepath.Join(stateDir(), statusFile)
	st, err := daemon.ReadStatus(path)
	if err != nil {
		desired, derr := daemon.ReadDesired(filepath.Join(stateDir(), desiredFile))
		if derr != nil {
			desired = daemon.Down
		}
		st = daemon.Status{Desired: desired, UpdatedAt: time.Now()}
	}
	st.Contested = contested
	if err := daemon.WriteStatus(path, st); err != nil {
		fmt.Fprintf(os.Stderr, "не записать contested в статус: %v\n", err)
	}
}

// cmdUp поднимает всё вручную: та же процедура S1-S6, что у heal, но как
// свежий полный bring-up -- каждый шаг ensure-then-verify по порядку,
// без предварительной сверки (VerifyAll). Затем up записывает желаемое
// состояние демону -- дальше конвергенцией владеет его probe-loop.
func cmdUp() error { return runUp(context.Background()) }

func runUp(ctx context.Context) error {
	dir := stateDir()
	// Ручное действие = свежее намерение пользователя: снятие блокировки
	// (ADR-005) позволяет heal продолжить попытки после этого up.
	if err := authstate.Reset(dir); err != nil {
		return err
	}
	steps, err := healBuildSteps(ctx) // общий с heal ассемблер corpEnv + S1..S6
	if err != nil {
		return err
	}
	for _, s := range steps {
		fmt.Printf("%s ...\n", s.Name)
		// Ошибки шагов уже обёрнуты именем шага (stepWrap), поэтому main
		// печатает ровно "ошибка: <step>: <err>" и выходит с кодом 1.
		if err := s.Ensure(ctx); err != nil {
			return err
		}
		if err := s.Verify(ctx); err != nil {
			return err
		}
		fmt.Printf("%s ok\n", s.Name)
	}
	// Туннель поднят; застрявший счётчик только отложил бы разморозку до
	// следующего успешного прохода heal, поэтому не фатально.
	if err := authstate.RecordAuthSuccess(dir); err != nil {
		fmt.Fprintf(os.Stderr, "не сбросить счётчик авторизаций: %v\n", err)
	}
	recordDesired(daemon.Up)
	fmt.Println("\nготово. Проверка: corpvpn check")
	return nil
}

// sudoDNSFwdDown stops the forwarder through the sudoers grant
// (`sudo -n <self> root-dns-fwd down`), the unprivileged half of the
// net-down ⟺ dns-fwd down pairing. Seam: tests inject a fake.
var sudoDNSFwdDown = func(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		self = "corpvpn"
	}
	_, err = sudoExec(ctx, []string{"-n", self, "root-dns-fwd", "down"}, nil)
	return err
}

// stopForwarderAfterNetDown keeps the pairing in one place: down must leave
// no forwarder process behind. Best-effort -- a warning, never a failure.
func stopForwarderAfterNetDown(ctx context.Context) {
	if err := sudoDNSFwdDown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "root-dns-fwd down: %v (форвардер мог остаться живым)\n", err)
	}
}

// hostNetDown снимает маршруты и DNS на Mac. Сначала -- беспарольный путь
// через sudoers-грант ADR-002 (`sudo -n corpvpn root-net-down`); если гранта
// нет (sudo отказал, команда не стартовала -- reached=false), откатываемся к
// прежнему интерактивному route-down.sh, который сам спросит пароль. Оба пути
// откатывают одни и те же файлы состояния: root-net-up пишет форматы
// route-down.sh намеренно, поэтому down не меняет смысла, только просит пароль
// всё реже. В конце успеха в обоих путях гасится DNS-форвардер (design.md:
// down останавливает то, что S5 запустил).
func hostNetDown(ctx context.Context, runSudo func(context.Context, []string, []string) (bool, error), routeDown func() error) error {
	// environ=nil: наследуем окружение, stateDir() под sudo резолвится через
	// SUDO_USER -- отдельных оверрайдов root-net-down не требует.
	reached, err := runSudo(ctx, []string{"-n", "corpvpn", "root-net-down"}, nil)
	if err == nil {
		stopForwarderAfterNetDown(ctx)
		return nil
	}
	if reached {
		return err // root-net-down отработал и упал по существу, не из-за гранта
	}
	if err := routeDown(); err != nil {
		return err
	}
	stopForwarderAfterNetDown(ctx)
	return nil
}

func cmdDown() error {
	removeWatchdogAgent() // чтобы не воскрешал специально погашенный туннель
	// Сначала снимаем маршруты и DNS на Mac -- это надо сделать даже если VM уже нет.
	if err := hostNetDown(context.Background(), sudoExec, hostRouteDown); err != nil {
		fmt.Fprintf(os.Stderr, "маршруты на Mac снялись с ошибкой: %v\n", err)
	}
	if !vmRunning() {
		fmt.Println("VM не запущена -- на Mac всё снято")
		recordDesired(daemon.Down)
		return nil
	}
	ovpnDown() // погасить OpenVPN (tun1), если поднят
	stopCisco()
	if err := guestPassthrough("sudo", guestDir+"/guest/egress-down.sh"); err != nil {
		return err
	}
	fmt.Println("туннель погашен, egress напрямую")
	recordDesired(daemon.Down)
	notify("🖕 VPN отключён")
	return nil
}

// cmdRootNetUp применяет маршруты и DNS на Mac из .env/состояния гостя.
// Запускается как root через `sudo -n corpvpn root-net-up` (sudoers-grant,
// ADR-002): без TTY и без вопросов -- все значения валидируются до того,
// как что-то меняется в системе.
func cmdRootNetUp() error {
	cfg, err := hostOpsConfig()
	if err != nil {
		return err
	}
	rep, err := hostops.ApplyNetReport(context.Background(), cfg, hostops.RealExec)
	// Конкурентные адреса производит именно этот процесс; пишем их в файл
	// статуса даже при частичной ошибке прохода -- увиденное правдиво.
	recordContested(rep.Contested)
	return err
}

// cmdRootNetDown снимает то, что накатил root-net-up (те же файлы состояния).
func cmdRootNetDown() error {
	return hostops.RemoveNet(context.Background(), stateDir(), hostops.RealExec)
}

// hostOpsConfig собирает hostops.Config для root-net-up. Сначала читаем
// оверрайды из окружения (CORPVPN_STATE_DIR/CORPVPN_GATEWAY/CORPVPN_SUBNETS):
// под sudo ни limactl (инстансы per-user; route-up.sh обходит это через
// sudo -u REAL_USER), ни $HOME (это /var/root) не работают, поэтому
// непривилегированный вызывающий передаёт всё готовым. .env и derivation --
// только когда оверрайда нет (обычный интерактивный запуск).
func hostOpsConfig() (hostops.Config, error) {
	cfg := hostops.Config{
		StateDir:    stateDir(),
		CorpDomains: strings.Fields(os.Getenv("CORP_DOMAINS")),
		OVPNDomains: strings.Fields(os.Getenv("OVPN_DOMAINS")),
		CorpDNS:     strings.Fields(os.Getenv("CORP_DNS")),
		DNSMode:     env("DNS_MODE", "primary"),
	}
	switch raw := os.Getenv("CORPVPN_SUBNETS"); {
	case raw != "":
		subnets, err := parsePrefixFields(raw)
		if err != nil {
			return hostops.Config{}, err
		}
		cfg.Subnets = subnets
	case os.Getenv("CORP_SUBNETS") != "":
		subnets, err := parsePrefixFields(os.Getenv("CORP_SUBNETS"))
		if err != nil {
			return hostops.Config{}, err
		}
		cfg.Subnets = subnets
	default:
		// Пустой kept-set (S5 исключил все адреса, либо запуск без
		// оверрайда) обязан остаться пустым: bulk-derivation из гостя
		// убран, root не выдумывает маршруты, которые ему не передали.
		cfg.Subnets = nil
	}
	// Все три ветки сходятся сюда: CORP_EXCLUDE_SUBNETS применяется один раз
	// до ApplyNet, битые записи -- жёсткая ошибка до любых изменений в системе.
	kept, removed, err := filterSubnets(cfg.Subnets, os.Getenv("CORP_EXCLUDE_SUBNETS"))
	if err != nil {
		return hostops.Config{}, err
	}
	cfg.Subnets = kept
	for _, p := range removed {
		fmt.Fprintf(os.Stderr, "excluded by CORP_EXCLUDE_SUBNETS: %s\n", p)
	}
	if gw := os.Getenv("CORPVPN_GATEWAY"); gw != "" {
		cfg.IfaceGateway = gw
	} else {
		gw, err := vmIP()
		if err != nil {
			return hostops.Config{}, err
		}
		cfg.IfaceGateway = gw
	}
	return cfg, nil
}

// filterSubnets applies CORP_EXCLUDE_SUBNETS to a resolved subnet set.
// Malformed exclusion entries are a hard error: the caller must abort
// before any mutation.
func filterSubnets(subnets []netip.Prefix, excludeList string) ([]netip.Prefix, []netip.Prefix, error) {
	var excludes []netip.Prefix
	for _, s := range strings.Fields(excludeList) {
		p, err := netutil.ParseCIDRStrict(s)
		if err != nil {
			return nil, nil, err
		}
		excludes = append(excludes, p)
	}
	kept, removed := netutil.FilterExcluded(subnets, excludes)
	return kept, removed, nil
}

// parsePrefixFields strict-parses a space-separated prefix list.
func parsePrefixFields(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range strings.Fields(raw) {
		p, err := netutil.ParseCIDRStrict(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Root verb seams: the dispatch calls these wrappers, tests inject fakes
// (same pattern as healBuildSteps). Defaults wire the real internal/verbs
// implementations with the production exec and file helpers.
var (
	verbFlushClonedRoutes = func(iface string) error {
		return verbs.FlushClonedRoutes(iface, hostops.RealExec)
	}
	verbResolverKick = func() error {
		return verbs.ResolverKick(hostops.RealExec)
	}
	verbHostsUp = func(entries []verbs.HostsEntry) error {
		return verbs.HostsUp(hostsFile, entries, os.ReadFile, os.WriteFile)
	}
	verbHostsDown = func() error {
		return verbs.HostsDown(hostsFile, os.ReadFile, os.WriteFile)
	}
	verbDNSFwdUp = func(selfPath, bankDomain, upstream, pidPath string) (int, error) {
		return verbs.DNSFwdUp(selfPath, bankDomain, upstream, pidPath)
	}
	verbDNSFwdDown = func(pidPath string) error {
		return verbs.DNSFwdDown(pidPath)
	}
	verbDNSFwdRun = verbs.DNSFwdRun
)

// daemonRun is the seam for the daemon loop itself: cmdDaemon builds the
// paths from the state dir, tests replace the whole loop so dispatch never
// starts a live probe cycle.
var daemonRun = func(ctx context.Context) error {
	d := daemon.Daemon{
		DesiredPath: filepath.Join(stateDir(), desiredFile),
		StatusPath:  filepath.Join(stateDir(), statusFile),
		Probe:       daemonProbe,
		Reconcile:   daemonReconcile,
		EachTick:    newWedgeDriver().eachTick,
	}
	return d.Run(ctx)
}

// probeConfig resolves the daemon probe target from the bank config
// contract: BANK_DOMAIN (default wb-bank.ru) and BANK_PROBE_HOST (default
// btg.wb-bank.ru). CHECK_HOSTS is a dead contract and is not read; an
// invalid bank config errors so the probe surfaces red in the status file.
func probeConfig() (domain, host string, err error) {
	bc, err := loadBankConfig(os.Getenv)
	if err != nil {
		return "", "", err
	}
	return bc.BankDomain, bc.BankProbeHost, nil
}

// daemonProbe is the daemon's production Probe: resolve the bank domain
// and dial the check host -- the same end-to-end probe S6 uses.
var daemonProbe = func(ctx context.Context) error {
	domain, host, err := probeConfig()
	if err != nil {
		return err
	}
	return probe.New().Check(ctx, domain, host)
}

// daemonReconcile is the daemon's production Reconcile. It mirrors the
// cmdHeal discipline (heal.go) but reports every verdict through the
// daemon's callback: parked credentials never rebuild the tunnel (ADR-005);
// all steps verify before anything repairs, so one pass records the whole
// picture; the repair cascade starts at the first broken step and stops at
// the first error, feeding the auth breaker on the way.
var daemonReconcile = func(ctx context.Context, report func(step string, err error)) error {
	dir := stateDir()
	if parked, _ := authstate.IsParked(dir); parked {
		report("auth", errors.New("учётные данные отклонены ранее; выполни corpvpn creds, затем corpvpn up"))
		return nil
	}
	steps, err := healBuildSteps(ctx)
	if err != nil {
		report("env", err)
		return nil
	}
	firstBroken := ""
	for _, s := range steps {
		verr := s.Verify(ctx)
		report(s.Name, verr)
		if verr != nil && firstBroken == "" {
			firstBroken = s.Name
		}
	}
	if firstBroken == "" {
		return authstate.RecordAuthSuccess(dir)
	}
	start := 0
	for i, s := range steps {
		if s.Name == firstBroken {
			start = i
			break
		}
	}
	var cascadeErr error
	for _, s := range steps[start:] {
		if eerr := s.Ensure(ctx); eerr != nil {
			report(s.Name, eerr)
			cascadeErr = eerr
			break
		}
		verr := s.Verify(ctx)
		report(s.Name, verr)
		if verr != nil {
			cascadeErr = verr
			break
		}
	}
	if cascadeErr == nil {
		return authstate.RecordAuthSuccess(dir)
	}
	if failure.Classify(cascadeErr) == failure.Auth {
		// RecordAuthFailure parks by itself after MaxConsecutive; an
		// unreadable counter parks too (fail-safe, as in heal.go) and is
		// surfaced through the same pseudo-step.
		if _, ferr := authstate.RecordAuthFailure(dir); ferr != nil {
			report("auth", ferr)
		}
	}
	return cascadeErr
}

// wedgeDriver pairs the WedgeWatcher with the daemon tick counter: Cycle
// needs a cycle number that starts at 1 and grows once per tick. The cache
// is re-read every tick -- the forwarder refreshes it as it answers.
type wedgeDriver struct {
	watcher *daemon.WedgeWatcher
	cycle   func(ctx context.Context, n int, cache []verbs.HostsEntry)
	ticks   int
}

func (wd *wedgeDriver) eachTick(ctx context.Context) {
	wd.ticks++
	wd.cycle(ctx, wd.ticks, cachedHostsEntries(stateDir()))
}

// newWedgeDriver builds the production watcher: the probe host comes from
// the bank config, the forwarder sits on 127.0.0.1, the scoped lookup and
// the forwarder answer are probed the same way S5/S6 probe them, repairs go
// through the sudoers-granted root verbs. An invalid bank config falls back
// to the default host: the probe already surfaces the config error red, the
// watcher stays able to run.
func newWedgeDriver() *wedgeDriver {
	host := defaultBankProbeHost
	if bc, err := loadBankConfig(os.Getenv); err == nil {
		host = bc.BankProbeHost
	}
	w := &daemon.WedgeWatcher{
		TestHost:      host,
		ForwarderAddr: forwarderAddr,
		ScopedLookup: func(ctx context.Context, h string) bool {
			return verbs.ScopedLookupWorks(ctx, hostops.RealExec, h)
		},
		ForwarderAnswers: forwarderResolves,
		Kick:             func() error { return sudoVerb("root-resolver-kick") },
		HostsUp: func([]verbs.HostsEntry) error {
			// The root verb re-reads the forwarder cache itself.
			return sudoVerb("root-hosts-up")
		},
		// Plain notify: the watcher dedups per episode itself (one
		// notification per wedge episode is the design contract).
		Notify: notify,
	}
	return &wedgeDriver{watcher: w, cycle: w.Cycle}
}

// sudoVerb runs one sudoers-granted root verb from the unprivileged daemon:
// fixed argv, inherited environment (stateDir() under sudo resolves via
// SUDO_USER).
func sudoVerb(verb string) error {
	self, err := os.Executable()
	if err != nil {
		self = "corpvpn"
	}
	_, err = sudoExec(context.Background(), []string{"-n", self, verb}, nil)
	return err
}

// forwarderResolves answers whether the scoped forwarder resolves host,
// through a pure-Go resolver pinned to the forwarder (the same dial pattern
// defaultBankAddrs uses): a wedged system resolver must not skew the answer.
func forwarderResolves(ctx context.Context, host string) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, forwarderAddr+":53")
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := r.LookupHost(cctx, host)
	return err == nil && len(names) > 0
}

// cmdDaemon is the launchd entry of the desired-state daemon: the
// probe-and-converge loop runs until SIGINT/SIGTERM; KeepAlive restarts
// the process on exit.
func cmdDaemon() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return daemonRun(ctx)
}

// cachedHostsEntries reads the forwarder's answer cache (hosts-cache.json in
// the state dir, written by the forwarder/daemon) for the hosts fallback
// verb. Missing, unreadable or corrupt cache means "no entries".
func cachedHostsEntries(dir string) []verbs.HostsEntry {
	b, err := os.ReadFile(filepath.Join(dir, "hosts-cache.json"))
	if err != nil {
		return nil
	}
	var entries []verbs.HostsEntry
	if json.Unmarshal(b, &entries) != nil {
		return nil
	}
	return entries
}

// cmdRootDNSFwd is the root half of the forwarder lifecycle. The sudoers
// grant pins the argv to exactly `root-dns-fwd up|down` (install.sh), so
// the bank domain and the upstream server come from the environment the
// unprivileged caller passes (BANK_DOMAIN, CORP_DNS), never from arguments.
func cmdRootDNSFwd(args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	pidPath := filepath.Join(stateDir(), dnsFwdPid)
	switch sub {
	case "up":
		bc, err := loadBankConfig(os.Getenv)
		if err != nil {
			return err
		}
		dns := strings.Fields(os.Getenv("CORP_DNS"))
		if len(dns) == 0 {
			return fmt.Errorf("root-dns-fwd: CORP_DNS пуст -- форвардеру некуда пересылать запросы")
		}
		self, err := os.Executable()
		if err != nil {
			self = "corpvpn"
		}
		_, err = verbDNSFwdUp(self, bc.BankDomain, dns[0]+":53", pidPath)
		return err
	case "down":
		return verbDNSFwdDown(pidPath)
	}
	return fmt.Errorf("root-dns-fwd up|down")
}
