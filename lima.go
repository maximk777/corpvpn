package main

// Оркестрация гостя. Всё, что делается внутри VM, идёт через limactl shell.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	vmName    = "vpnbox"
	guestDir  = "/opt/corpvpn"
	tmuxName  = "vpn"
	egressTun = "tun-egress"
	vpnTun    = "tun0"
)

// guest выполняет команду в госте и возвращает stdout.
// limactl шумит логами в stderr -- он отделён и в результат не попадает.
func guest(args ...string) (string, error) {
	full := append([]string{"shell", vmName, "--"}, args...)
	cmd := exec.Command("limactl", full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("в госте не отработало %v: %w: %s",
			args, err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func guestPassthrough(args ...string) error {
	full := append([]string{"shell", vmName, "--"}, args...)
	cmd := exec.Command("limactl", full...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func vmRunning() bool {
	out, err := exec.Command("limactl", "list", vmName, "--format", "{{.Status}}").Output()
	return err == nil && strings.TrimSpace(string(out)) == "Running"
}

func ensureVM() error {
	if vmRunning() {
		return nil
	}
	fmt.Fprintf(os.Stderr, "поднимаю VM %s...\n", vmName)
	cmd := exec.Command("limactl", "start", vmName, "--tty=false")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func ifaceUp(name string) bool {
	_, err := guest("ip", "link", "show", name)
	return err == nil
}

// ensureEgress поднимает tun2socks, если он ещё не поднят. Идемпотентно:
// повторный запуск при живом туннеле ничего не ломает.
func ensureEgress(socksAddr string, proxyDNS bool) error {
	if ifaceUp(egressTun) {
		def, _ := guest("ip", "-4", "route", "show", "default")
		if strings.Contains(def, egressTun) {
			// Туннель уже есть -- но, возможно, в ДРУГОЙ прокси. Молча оставить
			// его значило бы дать думать, что трафик идёт через новый адрес.
			unit, _ := guest("systemctl", "show", "corpvpn-tun2socks",
				"-p", "ExecStart", "--value")
			if strings.Contains(unit, socksAddr) {
				return nil
			}
			fmt.Fprintf(os.Stderr, "egress поднят через другой прокси -- пересобираю на %s\n", socksAddr)
			if err := guestPassthrough("sudo", guestDir+"/guest/egress-down.sh"); err != nil {
				return err
			}
		}
	}
	dns := "0"
	if proxyDNS {
		dns = "1"
	}
	fmt.Fprintf(os.Stderr, "заворачиваю egress гостя в %s...\n", socksAddr)
	return guestPassthrough("sudo",
		"SOCKS_ADDR="+socksAddr, "PROXY_DNS="+dns,
		guestDir+"/guest/egress-up.sh")
}

// vpnSubnets -- подсети, доступные через туннель. Именно их надо прописать
// маршрутами на Mac, чтобы корп-хосты открывались по реальным адресам.
func vpnSubnets() ([]string, error) {
	out, err := guest("ip", "-4", "route", "show", "dev", vpnTun)
	if err != nil {
		return nil, err
	}
	var nets []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "default" {
			continue
		}
		nets = append(nets, f[0])
	}
	return nets, nil
}

func vmIP() (string, error) {
	// lima0 -- интерфейс vzNAT, единственный адрес гостя, маршрутизируемый с Mac.
	out, err := guest("sh", "-c", "ip -4 -o addr show dev lima0 | awk '{print $4}' | cut -d/ -f1")
	if err != nil {
		return "", err
	}
	if out == "" {
		return "", fmt.Errorf("у гостя нет адреса на lima0 -- в lima/vpnbox.yaml должен быть vzNAT")
	}
	return out, nil
}
