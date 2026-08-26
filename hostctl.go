package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// hostScript запускает host/<name> в интерактивном режиме: скрипт сам поднимает
// sudo на нужных шагах, поэтому пароль спрашивается прямо в терминале.
func hostScript(name string) error {
	path := filepath.Join(repoRoot(), "host", name)
	cmd := exec.Command("bash", path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = repoRoot()
	return cmd.Run()
}

func hostRouteUp() error   { return hostScript("route-up.sh") }
func hostRouteDown() error { return hostScript("route-down.sh") }

// notify шлёт macOS-уведомление (нативно, через osascript). Выключается NOTIFY=0.
// Работает и из watchdog-агента -- он крутится в GUI-сессии пользователя.
func notify(msg string) {
	if os.Getenv("NOTIFY") == "0" {
		return
	}
	// osascript работает из коробки (баннер/Центр уведомлений под "Script Editor").
	// terminal-notifier не берём: требует отдельного разрешения, которого обычно нет.
	esc := strings.ReplaceAll(msg, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	_ = exec.Command("osascript", "-e",
		fmt.Sprintf(`display notification "%s" with title "corpvpn"`, esc)).Run()
}

// macCurl бьёт по URL с самого Mac (через /etc/resolver и маршруты в гостя) --
// это ближе к реальному сценарию, чем curl из гостя со split-DNS.
func macCurl(url string) (string, error) {
	out, err := exec.Command("curl", "-sS", "--max-time", "12",
		"-o", "/dev/null", "-w", "%{http_code} %{remote_ip}", url).Output()
	return strings.TrimSpace(string(out)), err
}

const (
	socksAgentLabel    = "com.corpvpn.socks"
	watchdogAgentLabel = "com.corpvpn.watchdog"
)

// legacyAgentLabels -- прежние имена агентов (до переименований). Сносим при setup,
// чтобы два autossh не дрались за один порт.
var legacyAgentLabels = []string{
	"com.proxyprocess.rfsocks",
	"com.wbvpn.socks",
	"com.wbvpn.watchdog",
}

func launchctlBootout(label string) {
	_ = exec.Command("launchctl", "bootout", "gui/"+guiUID()+"/"+label).Run()
}

func launchctlBootstrap(plistPath string) error {
	if out, err := exec.Command("launchctl", "bootstrap", "gui/"+guiUID(), plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap не сработал: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func guiUID() string { return fmt.Sprintf("%d", os.Getuid()) }

func agentIsLoaded(label string) bool {
	return exec.Command("launchctl", "print", "gui/"+guiUID()+"/"+label).Run() == nil
}

// installWatchdogAgent ставит сервис, который раз в 30с зовёт `corpvpn heal`:
// если VPN упал -- поднимает заново (без sudo, из keychain). Путь к бинарю --
// текущий исполняемый файл, поэтому ставить надо уже установленным corpvpn.
func installWatchdogAgent() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	logPath := filepath.Join(home, "Library", "Logs", "corpvpn-watchdog.log")
	plistPath := filepath.Join(home, "Library", "LaunchAgents", watchdogAgentLabel+".plist")
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array><string>%s</string><string>heal</string></array>
  <key>StartInterval</key><integer>30</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, watchdogAgentLabel, self, logPath, logPath)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	launchctlBootout(watchdogAgentLabel)
	return launchctlBootstrap(plistPath)
}

func removeWatchdogAgent() { launchctlBootout(watchdogAgentLabel) }

// installSocksAgent ставит LaunchAgent, который держит autossh -D до РФ-хоста.
// Адрес хоста и локальный порт берутся из .env (SOCKS_HOST, SOCKS_ADDR),
// ничего не хардкодится.
func installSocksAgent() error {
	sshTarget := os.Getenv("SOCKS_HOST")
	if sshTarget == "" {
		return fmt.Errorf("не задан SOCKS_HOST (ssh-таргет РФ-хоста, напр. root@1.2.3.4) -- пропиши в .env")
	}
	bind := env("SOCKS_ADDR", "192.168.64.1:1081")
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	logPath := filepath.Join(home, "Library", "Logs", "corpvpn-socks.log")
	plistPath := filepath.Join(home, "Library", "LaunchAgents", socksAgentLabel+".plist")

	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/autossh</string>
    <string>-M</string><string>0</string>
    <string>-N</string>
    <string>-o</string><string>BatchMode=yes</string>
    <string>-o</string><string>StrictHostKeyChecking=accept-new</string>
    <string>-o</string><string>ExitOnForwardFailure=yes</string>
    <string>-o</string><string>ServerAliveInterval=15</string>
    <string>-o</string><string>ServerAliveCountMax=3</string>
    <string>-o</string><string>ConnectTimeout=15</string>
    <string>-D</string><string>%s</string>
    <string>%s</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>AUTOSSH_GATETIME</key><string>0</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>15</integer>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
`, socksAgentLabel, bind, sshTarget, logPath, logPath)

	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	for _, l := range legacyAgentLabels { // снести прежние агенты, иначе конфликт порта
		launchctlBootout(l)
	}
	launchctlBootout(socksAgentLabel)
	if err := launchctlBootstrap(plistPath); err != nil {
		return err
	}
	fmt.Printf("autossh-агент установлен: %s -> %s (SOCKS на %s)\n", socksAgentLabel, sshTarget, bind)
	fmt.Printf("логи: %s\n", logPath)
	return nil
}
