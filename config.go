package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Bank-world defaults of the .env contract.
const (
	defaultBankDomain    = "wb-bank.ru"
	defaultBankProbeHost = "btg.wb-bank.ru"
)

// BankConfig holds the bank-world keys of the .env contract.
type BankConfig struct {
	BankDomain    string
	BankProbeHost string
}

// loadBankConfig reads BANK_DOMAIN/BANK_PROBE_HOST; an empty value keeps
// the default. getenv is injectable for tests. Stale keys from an old
// .env (DNS_MODE, CHECK_HOSTS) are never read: the resolver behavior is
// the only DNS implementation and no error is raised about removed keys.
func loadBankConfig(getenv func(string) string) (BankConfig, error) {
	cfg := BankConfig{BankDomain: defaultBankDomain, BankProbeHost: defaultBankProbeHost}
	if v := getenv("BANK_DOMAIN"); v != "" {
		d, err := parseDomain(v)
		if err != nil {
			return BankConfig{}, fmt.Errorf("BANK_DOMAIN: %w", err)
		}
		cfg.BankDomain = d
	}
	if v := getenv("BANK_PROBE_HOST"); v != "" {
		h, err := parseDomain(v)
		if err != nil {
			return BankConfig{}, fmt.Errorf("BANK_PROBE_HOST: %w", err)
		}
		cfg.BankProbeHost = h
	}
	return cfg, nil
}

// parseDomain validates a strict domain name and returns it lowercased:
// dot-separated labels of [a-z0-9-], 1-63 chars each, hyphen only inside
// a label, at least two labels, 253 chars total. BANK_DOMAIN names an
// /etc/resolver file and a "*.domain" match, so a single-label name
// cannot work there.
func parseDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("%q: longer than 253 chars", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("%q: need at least two labels", d)
	}
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("%q: empty label", d)
		}
		if len(l) > 63 {
			return "", fmt.Errorf("%q: label %q is longer than 63 chars", d, l)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("%q: label %q has a leading/trailing hyphen", d, l)
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("%q: label %q has invalid character %q", d, l, r)
			}
		}
	}
	return d, nil
}

// repoRoot -- каталог с host/route-up.sh: ищем от cwd вверх, потом рядом с бинарём.
// Нужен, чтобы `up`/`down` находили host-скрипты и .env независимо от того,
// откуда запущен бинарь.
func repoRoot() string {
	marker := filepath.Join("host", "route-up.sh")
	if dir, err := os.Getwd(); err == nil {
		for {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if exe, err := os.Executable(); err == nil {
		// corpvpn ставится симлинком в /usr/local/bin -- резолвим его до реального
		// dist/corpvpn внутри репо, иначе host/*.sh рядом не найдётся.
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		for {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				return dir
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "."
}

// stateDir -- Mac-состояние (то же, что host/route-*.sh: ~/.local/state/corpvpn).
// CORPVPN_STATE_DIR сильнее всего: под sudo $HOME -- это /var/root, поэтому
// непривилегированный вызывающий передаёт каталог явно. Без оверрайда берём
// дом реального юзера (SUDO_USER), как route-up.sh:12-15, -- иначе
// root-net-up/root-net-down записали бы состояние там, где route-down.sh его
// не найдёт.
func stateDir() string {
	if v := os.Getenv("CORPVPN_STATE_DIR"); v != "" {
		return v
	}
	home := sudoUserHome()
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return filepath.Join(".", ".state")
		}
		home = h
	}
	return filepath.Join(home, ".local", "state", "corpvpn")
}

// sudoUserHome resolves the pre-sudo user's home directory via SUDO_USER,
// mirroring host/route-up.sh:12-15. Empty when not under sudo or on lookup
// failure -- callers fall back to the current user's home.
func sudoUserHome() string {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		return ""
	}
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// readGatewayPref -- сохранённый через `gw` выбор шлюза (пусто, если не выбирали).
func readGatewayPref() string {
	b, err := os.ReadFile(filepath.Join(stateDir(), "gateway"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeGatewayPref(gw string) error {
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir(), "gateway"), []byte(gw+"\n"), 0o644)
}

// loadDotEnv подхватывает .env из корня репо. Уже заданные в окружении
// переменные не трогаем -- явный экспорт всегда сильнее файла.
func loadDotEnv() {
	f, err := os.Open(filepath.Join(repoRoot(), ".env"))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key != "" {
			if _, exists := os.LookupEnv(key); !exists {
				_ = os.Setenv(key, val)
			}
		}
	}
	_ = sc.Err()
}
