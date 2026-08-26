package main

// Интерактивная аутентификация через псевдотерминал.
//
// openconnect живёт в detached-сессии tmux ВНУТРИ гостя, а мы подключаемся
// к ней через pty. Это даёт три вещи:
//   1. туннель переживает обрыв ssh -- сессией владеет tmux, а не наш процесс;
//   2. секреты идут только через pty: их нет ни в argv, ни в env, ни на диске;
//   3. всё, что мы не распознали, видит и дотыкает человек -- терминал сквозной.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

var (
	reUsername = regexp.MustCompile(`(?i)(username|login|user)\s*[:?]\s*$`)
	rePassword = regexp.MustCompile(`(?i)(password|пароль)\s*[:?]\s*$`)
	// Шлюзы Cisco называют второй фактор по-разному, поэтому список широкий.
	reToken = regexp.MustCompile(`(?i)(token|otp|passcode|one[- ]?time|verification|challenge|answer|response|код)\s*[^\n]{0,20}[:?]\s*$`)
	// openconnect печатает это, когда туннель уже поднят.
	// Шлюзы печатают успех по-разному: openconnect старых версий -- "Connected tun0",
	// шлюз печатает "CSTP connected" и "Configured as 10.x". Список широкий, но все маркеры
	// печатаются только ПОСЛЕ того, как туннель встал.
	reConnected = regexp.MustCompile(`(?i)(connected\s+` + vpnTun + `|connected as [\d.]|configured as [\d.]|cstp connected|established (dtls|tls) connection)`)
	reAuthFail  = regexp.MustCompile(`(?i)(login failed|authentication failed|invalid credentials|permission denied)`)
)

type authAgent struct {
	username  string
	password  string
	totp      *totpConfig
	pwSent    int
	tokenSent int
}

// answer решает, что отправить в ответ на хвост вывода. Второе и последующие
// приглашения вида "Password:" -- это уже челлендж второго фактора: шлюзы Cisco
// часто переиспользуют ту же подпись для поля secondary_password.
func (a *authAgent) answer(tail string) (value, label string, ok bool) {
	switch {
	case reToken.MatchString(tail):
		return a.tokenValue()
	case rePassword.MatchString(tail):
		if a.pwSent == 0 {
			a.pwSent++
			return a.password, "пароль", true
		}
		return a.tokenValue()
	case reUsername.MatchString(tail) && a.username != "":
		return a.username, "логин", true
	}
	return "", "", false
}

func (a *authAgent) tokenValue() (string, string, bool) {
	if a.totp == nil {
		return "", "", false
	}
	now := time.Now()
	// Если код доживает меньше пяти секунд, шлюз может не успеть его принять.
	if left := a.totp.validFor(now); left < 5 {
		time.Sleep(time.Duration(left+1) * time.Second)
		now = time.Now()
	}
	a.tokenSent++
	return a.totp.codeAt(now), "TOTP-код", true
}

// runAuth подключается к tmux-сессии гостя и ведёт диалог аутентификации.
func runAuth(agent *authAgent, timeout time.Duration) error {
	cmd := exec.Command("limactl", "shell", vmName, "--",
		"sudo", "tmux", "attach-session", "-t", tmuxName)
	// limactl протаскивает TERM хоста в гостя. Экзотический TERM (напр. xterm-ghostty)
	// у гостя без terminfo -- tmux attach падает "unsuitable terminal". Форсируем базовый.
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("не поднять pty: %w", err)
	}
	defer func() { _ = ptmx.Close() }()

	if ws, err := pty.GetsizeFull(os.Stdin); err == nil {
		_ = pty.Setsize(ptmx, ws)
	}
	if state, err := term.MakeRaw(int(os.Stdin.Fd())); err == nil {
		defer func() { _ = term.Restore(int(os.Stdin.Fd()), state) }()
	}

	// Нераспознанные приглашения набирает человек.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	var tail strings.Builder

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("аутентификация не уложилась в %s", timeout)
		}
		_ = ptmx.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := ptmx.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = os.Stdout.Write(chunk)
			tail.WriteString(string(chunk))
			if tail.Len() > 8192 {
				s := tail.String()
				tail.Reset()
				tail.WriteString(s[len(s)-4096:])
			}
			cur := tail.String()

			if reAuthFail.MatchString(cur) {
				return fmt.Errorf("шлюз отверг учётные данные")
			}
			if reConnected.MatchString(cur) {
				// Ctrl-B d -- отцепиться от tmux, оставив туннель жить.
				_, _ = ptmx.Write([]byte{0x02, 'd'})
				time.Sleep(500 * time.Millisecond)
				return nil
			}
			if value, label, ok := agent.answer(cur); ok {
				fmt.Fprintf(os.Stderr, "\r\n[corpvpn] подставляю %s\r\n", label)
				_, _ = ptmx.Write([]byte(value + "\r"))
				tail.Reset()
			}
		}
		if readErr != nil {
			if os.IsTimeout(readErr) {
				continue
			}
			if readErr == io.EOF {
				return fmt.Errorf("сессия закрылась до того, как туннель поднялся")
			}
			return readErr
		}
	}
}

// startTmuxSession перезапускает openconnect в detached-сессии tmux.
func startTmuxSession(gateway, user string, noDTLS bool) error {
	_, _ = guest("sudo", "tmux", "kill-session", "-t", tmuxName)

	oc := []string{"openconnect", "--protocol=anyconnect",
		"--script=/usr/share/vpnc-scripts/vpnc-script"}
	if user != "" {
		oc = append(oc, "--user="+user)
	}
	if noDTLS {
		// Проверено на этой машине: UDP через SOCKS5 не ходит, DTLS не поднимется.
		oc = append(oc, "--no-dtls")
	}
	oc = append(oc, gateway)

	_, err := guest("sudo", "tmux", "new-session", "-d", "-s", tmuxName,
		strings.Join(oc, " "))
	return err
}
