package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Tunnel 解析一份 wg-quick 配置，负责：起接口、策略路由规则、接口地址。
type Tunnel struct {
	Conf      TunnelConf
	Base      netip.Addr // Address 中第一个 IPv6
	Prefix    netip.Prefix
	PoolIID   uint64 // 随机池起始 IID
	StickyIID uint64

	seedMu     sync.Mutex
	seedByMark map[int]netip.Addr
}

// BuildSeedMarks 装配旧 sing-box 兼容规则：username -> 地址（seed_accounts），
// username -> mark（seed_marks）。mark 固定 SNAT 到对应地址。
func (t *Tunnel) BuildSeedMarks(accounts map[string]string, marks map[string]int) {
	t.seedMu.Lock()
	defer t.seedMu.Unlock()
	t.seedByMark = map[int]netip.Addr{}
	for user, mark := range marks {
		addrStr, ok := accounts[user]
		if !ok {
			continue
		}
		addr, err := parseIPv6Addr(addrStr)
		if err == nil && t.Prefix.Contains(addr) {
			t.seedByMark[mark] = addr
		}
	}
}

func parseTunnel(conf TunnelConf) (*Tunnel, error) {
	raw, err := os.ReadFile(conf.WGConf)
	if err != nil {
		return nil, fmt.Errorf("tunnel %s: read %s: %w", conf.Name, conf.WGConf, err)
	}
	prefix, err := firstV6Address(string(raw))
	if err != nil {
		return nil, fmt.Errorf("tunnel %s: %w", conf.Name, err)
	}
	t := &Tunnel{Conf: conf, Prefix: prefix, Base: prefix.Addr()}
	poolStart, err := parseIID(prefix, conf.PoolStart)
	if err != nil {
		return nil, fmt.Errorf("tunnel %s: pool_start %s: %w", conf.Name, conf.PoolStart, err)
	}
	stickyStart, err := parseIID(prefix, conf.StickyStart)
	if err != nil {
		return nil, fmt.Errorf("tunnel %s: sticky_start %s: %w", conf.Name, conf.StickyStart, err)
	}
	t.PoolIID = poolStart
	t.StickyIID = stickyStart
	return t, nil
}

// parseIID 解析区间起始地址：支持完整地址（须在前缀内）或 IID 简写（如 ::10，
// 高 64 位为 0 时按前缀拼接）。
func parseIID(prefix netip.Prefix, s string) (uint64, error) {
	a, err := parseIPv6Addr(s)
	if err != nil {
		return 0, err
	}
	if !prefix.Contains(a) {
		b := a.As16()
		if beUint64(b[:8]) != 0 {
			return 0, fmt.Errorf("address %s not in %s", a, prefix)
		}
	}
	return iidOf(a), nil
}

// firstV6Address 从 wg-quick 配置的 [Interface] Address 行提取第一个 IPv6 前缀。
func firstV6Address(conf string) (netip.Prefix, error) {
	inIface := false
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inIface = strings.EqualFold(line, "[Interface]")
			continue
		}
		if !inIface || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(k), "Address") {
			for _, a := range strings.Split(v, ",") {
				a = strings.TrimSpace(a)
				if !strings.Contains(a, ":") {
					continue
				}
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return netip.Prefix{}, fmt.Errorf("bad Address %q: %w", a, err)
				}
				if p.Addr().Is6() {
					if p.Bits() > 64 {
						return netip.Prefix{}, fmt.Errorf("Address %q: need /64 or shorter (IID 空间)", a)
					}
					return p, nil
				}
			}
		}
	}
	return netip.Prefix{}, fmt.Errorf("no IPv6 Address= in [Interface]")
}

func (t *Tunnel) rulePref() int { return 10000 + t.Conf.Table }

func (t *Tunnel) nftName() string {
	name := strings.Map(func(r rune) rune {
		if r == '-' {
			return '_'
		}
		return r
	}, t.Conf.Name)
	return "route64_proxy_" + name
}

// GenerateRuntimeConf 生成 wg-quick 运行时配置：接管 Table/PostUp/PostDown。
// 原始文件不修改；/etc/wireguard/<name>.conf 有变化时先备份并写入。
// 返回运行时配置路径。
func (t *Tunnel) GenerateRuntimeConf(projectDir string) (string, error) {
	raw, err := os.ReadFile(t.Conf.WGConf)
	if err != nil {
		return "", err
	}
	var filtered []string
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "PostUp") || strings.HasPrefix(trim, "PostDown") ||
			strings.HasPrefix(trim, "PreUp") || strings.HasPrefix(trim, "PreDown") ||
			strings.HasPrefix(trim, "Table") {
			continue // 由程序接管；必须放在 [Interface] 内，不能追加到 [Peer] 后
		}
		filtered = append(filtered, line)
	}
	pref := t.rulePref()
	nftPath := filepath.Join(projectDir, "runtime", t.nftName()+".nft")
	inject := []string{
		"Table = " + fmt.Sprintf("%d", t.Conf.Table),
		fmt.Sprintf("PostUp = nft -f %s", nftPath),
		fmt.Sprintf("PostUp = ip -6 rule add pref %d from all fwmark %#x/0xff lookup %d 2>/dev/null || true", pref, t.Conf.Mark, t.Conf.Table),
		fmt.Sprintf("PostDown = ip -6 rule del pref %d from all fwmark %#x/0xff lookup %d 2>/dev/null || true", pref, t.Conf.Mark, t.Conf.Table),
		fmt.Sprintf("PostDown = nft delete table ip6 %s 2>/dev/null || true", t.nftName()),
	}
	var out []string
	inserted := false
	for _, line := range filtered {
		if !inserted && strings.HasPrefix(strings.TrimSpace(line), "[Peer]") {
			out = append(out, inject...)
			out = append(out, "")
			inserted = true
		}
		out = append(out, line)
	}
	if !inserted {
		out = append(out, inject...)
	}
	out = append(out, "")
	content := []byte(strings.Join(out, "\n"))

	dst := "/etc/wireguard/" + t.Conf.Name + ".conf"
	if old, err := os.ReadFile(dst); err == nil && !bytes.Equal(old, content) {
		bak := fmt.Sprintf("%s.%s.bak", dst, time.Now().Format("20060102-150405"))
		if err := os.WriteFile(bak, old, 0o600); err != nil {
			return "", fmt.Errorf("backup %s: %w", bak, err)
		}
	}
	if err := os.WriteFile(dst, content, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", dst, err)
	}
	return dst, nil
}

// EnsureUp：接口未 up 时用运行时配置 wg-quick up；已 up（systemd 管理）时
// 仍会替换其配置为程序版本，使 systemd 重启后也加载程序规则而非旧表。
func (t *Tunnel) EnsureUp(projectDir string, manage bool) error {
	runtimeConf, err := t.GenerateRuntimeConf(projectDir)
	if err != nil {
		return err
	}
	if _, err := exec.Command("ip", "link", "show", "dev", t.Conf.Name).Output(); err == nil {
		return nil // 已运行；conf 已被替换，重启即新逻辑
	}
	if !manage {
		return fmt.Errorf("tunnel %s: interface down and manage_wg=false", t.Conf.Name)
	}
	if out, err := exec.Command("wg-quick", "up", runtimeConf).CombinedOutput(); err != nil {
		return fmt.Errorf("wg-quick up %s: %w (%s)", t.Conf.Name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureRule：策略路由规则幂等（fwmark 低 8 位 + 对应路由表）。
// iproute2 按 argv 解析，pref/fwmark/lookup 必须拆开，不能写成 "pref 10064" 一个参数。
func (t *Tunnel) EnsureRule() error {
	out, _ := exec.Command("ip", "-6", "rule", "show").Output()
	needle := fmt.Sprintf("fwmark %#x/0xff lookup %d", t.Conf.Mark, t.Conf.Table)
	if bytes.Contains(out, []byte(needle)) {
		return nil
	}
	out, err := exec.Command("ip", "-6", "rule", "add",
		"pref", fmt.Sprintf("%d", t.rulePref()),
		"from", "all",
		"fwmark", fmt.Sprintf("%#x/0xff", t.Conf.Mark),
		"lookup", fmt.Sprintf("%d", t.Conf.Table)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// EnsureAddr：幂等在接口上添加 /128（粘性账号出口地址）。
func (t *Tunnel) EnsureAddr(addr netip.Addr) error {
	if _, err := exec.Command("ip", "-6", "addr", "replace", addr.String()+"/128", "dev", t.Conf.Name).CombinedOutput(); err != nil {
		return fmt.Errorf("addr add %s: %w", addr, err)
	}
	return nil
}

func (t *Tunnel) IIDAddr(iid uint64) netip.Addr { return addrFromIID(t.Prefix, iid) }
