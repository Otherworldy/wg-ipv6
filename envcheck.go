package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// checkEnv 校验运行环境；install=true 时尝试通过系统包管理器补齐缺失项。
func checkEnv(install bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (需要 ip addr / nft / SO_MARK 权限); try: sudo %s", filepath.Base(os.Args[0]))
	}
	var missing []string
	for _, cmd := range []string{"ip", "nft", "wg", "wg-quick"} {
		if _, err := exec.LookPath(cmd); err != nil {
			missing = append(missing, cmd)
		}
	}
	if len(missing) > 0 {
		if !install {
			return fmt.Errorf("missing required commands: %s (run with --install to auto-install)", strings.Join(missing, ", "))
		}
		if err := installDeps(missing); err != nil {
			return fmt.Errorf("auto-install failed: %w", err)
		}
	}
	if _, err := os.Stat("/sys/module/wireguard"); err != nil {
		if out, err := exec.Command("modprobe", "wireguard").CombinedOutput(); err != nil {
			return fmt.Errorf("wireguard kernel module not available: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func installDeps(missing []string) error {
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return fmt.Errorf("cannot detect distro: %w", err)
	}
	rel := string(osRelease)
	pkgs := map[string]string{
		"ip": "iproute2", "nft": "nftables",
		"wg": "wireguard-tools", "wg-quick": "wireguard-tools",
	}
	var names []string
	seen := map[string]bool{}
	for _, m := range missing {
		if p := pkgs[m]; p != "" && !seen[p] {
			seen[p] = true
			names = append(names, p)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if strings.Contains(rel, "ID=ubuntu") || strings.Contains(rel, "ID=debian") {
		if err := exec.Command("apt-get", "update", "-qq").Run(); err != nil {
			return fmt.Errorf("apt-get update: %w", err)
		}
		args := append([]string{"install", "-y", "-qq"}, names...)
		if out, err := exec.Command("apt-get", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get install: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if strings.Contains(rel, "ID=fedora") || strings.Contains(rel, "ID=rocky") || strings.Contains(rel, "ID=almalinux") {
		args := append([]string{"install", "-y"}, names...)
		if out, err := exec.Command("dnf", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("dnf install: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return fmt.Errorf("unsupported distro; install manually: %s", strings.Join(names, " "))
}
