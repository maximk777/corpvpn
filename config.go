package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

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
func stateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".state")
	}
	return filepath.Join(home, ".local", "state", "corpvpn")
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
