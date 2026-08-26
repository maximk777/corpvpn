package main

// Wildberries-OpenVPN в песочнице, рядом с Cisco. tun1, аутентификация по
// сертификату с зашифрованным ключом -- passphrase из keychain, ввод через pty.

import (
	"bytes"
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

const ovpnTun = "tun1"

var (
	reKeyPass  = regexp.MustCompile(`(?i)private key password`)
	reOvpnOK   = regexp.MustCompile(`(?i)initialization sequence completed`)
	reOvpnFail = regexp.MustCompile(`(?i)(auth_failed|password verification failed|cannot load|private key.*fail)`)
)

// guestWriteFile пишет данные в файл гостя (tmpfs) с правами 600.
func guestWriteFile(path string, data []byte) error {
	cmd := exec.Command("limactl", "shell", vmName, "--", "sudo", "sh", "-c",
		fmt.Sprintf(`mkdir -p "$(dirname %s)" && cat > %s && chmod 600 %s`, path, path, path))
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("запись %s в гостя: %w: %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ovpnUp поднимает OpenVPN в госте на tun1. Конфиг -> гостевой tmpfs,
// passphrase ключа из keychain вводится через pty.
func ovpnUp() error {
	cfg := os.Getenv("OVPN_CONFIG")
	if cfg == "" {
		return nil
	}
	pass, err := credGet(acctOVPNKey)
	if err != nil {
		return fmt.Errorf("нет passphrase ключа OpenVPN в keychain -- добавь через `corpvpn creds set`: %w", err)
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("не читается OVPN_CONFIG %s: %w", cfg, err)
	}
	const guestCfg = "/run/corpvpn/wb.ovpn"
	if err := guestWriteFile(guestCfg, data); err != nil {
		return err
	}
	if err := guestPassthrough("sudo", guestDir+"/guest/ovpn-up.sh", guestCfg); err != nil {
		return fmt.Errorf("ovpn-up.sh: %w", err)
	}
	if err := runOvpnAuth(pass, 90*time.Second); err != nil {
		return err
	}
	if !ifaceUp(ovpnTun) {
		return fmt.Errorf("openvpn не поднял %s -- `limactl shell %s -- sudo tmux attach -t ovpn`", ovpnTun, vmName)
	}
	// форвардинг теперь и для tun1
	if err := guestPassthrough("sudo", guestDir+"/guest/expose-up.sh"); err != nil {
		return fmt.Errorf("форвардинг tun1: %w", err)
	}
	return nil
}

func ovpnDown() {
	_ = guestPassthrough("sudo", guestDir+"/guest/ovpn-down.sh")
}

// runOvpnAuth подключается к tmux-сессии 'ovpn' и вводит passphrase ключа,
// когда openvpn его спрашивает. Успех -- "Initialization Sequence Completed".
func runOvpnAuth(keyPass string, timeout time.Duration) error {
	cmd := exec.Command("limactl", "shell", vmName, "--",
		"sudo", "tmux", "attach-session", "-t", "ovpn")
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
	defer ttyPassthrough(ptmx)()

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 4096)
	var tail strings.Builder
	sent := false
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("openvpn не уложился в %s", timeout)
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
			if reOvpnFail.MatchString(cur) {
				return fmt.Errorf("openvpn отверг ключ/аутентификацию")
			}
			if reOvpnOK.MatchString(cur) {
				_, _ = ptmx.Write([]byte{0x02, 'd'}) // Ctrl-B d -- отцепиться, оставить жить
				time.Sleep(500 * time.Millisecond)
				return nil
			}
			if !sent && reKeyPass.MatchString(cur) {
				fmt.Fprintf(os.Stderr, "\r\n[corpvpn] ввожу passphrase ключа OpenVPN\r\n")
				_, _ = ptmx.Write([]byte(keyPass + "\r"))
				sent = true
				tail.Reset()
			}
		}
		if readErr != nil {
			if os.IsTimeout(readErr) {
				continue
			}
			if readErr == io.EOF {
				return fmt.Errorf("сессия openvpn закрылась до старта туннеля")
			}
			return readErr
		}
	}
}
