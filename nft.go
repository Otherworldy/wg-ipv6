package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BuildNFT 生成单个隧道 nftables 表文本：
//  1. mark 匹配且源地址不是基础地址的流量 -> accept（粘性账号已绑定的 /128，不做随机 SNAT）
//  2. mark 匹配 -> numgen 随机 SNAT（默认账号每次新连接随机出口）
func (t *Tunnel) BuildNFT() (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "table ip6 %s {\n", t.nftName())
	fmt.Fprintf(&b, "    chain postrouting {\n")
	fmt.Fprintf(&b, "        type nat hook postrouting priority srcnat; policy accept;\n")
	// 旧 sing-box 兼容：mark 0x140/0x240 -> 固定 SNAT（26183 旧客户端 acc1/acc2 行为不变）
	t.seedMu.Lock()
	compat := make(map[int]netip.Addr, len(t.seedByMark))
	for k, v := range t.seedByMark {
		compat[k] = v
	}
	t.seedMu.Unlock()
	for _, mark := range sortedMarks(compat) {
		fmt.Fprintf(&b, "        meta mark %#x counter snat to %s\n", mark, compat[mark])
	}
	fmt.Fprintf(&b, "        meta mark %#x ip6 saddr != %s/128 counter accept\n", t.Conf.Mark, t.Base)
	if t.Conf.PoolSize > 0 {
		fmt.Fprintf(&b, "        meta mark %#x counter snat to numgen random mod %d map {\n", t.Conf.Mark, t.Conf.PoolSize)
		for i := 0; i < t.Conf.PoolSize; i++ {
			addr := t.IIDAddr(t.PoolIID + uint64(i))
			sep := ","
			if i == t.Conf.PoolSize-1 {
				sep = ""
			}
			fmt.Fprintf(&b, "            %d : %s%s\n", i, addr, sep)
		}
		fmt.Fprintf(&b, "        }\n")
	}
	fmt.Fprintf(&b, "    }\n}\n")
	return b.String(), nil
}

func (t *Tunnel) WriteNFT(projectDir string) (string, error) {
	content, err := t.BuildNFT()
	if err != nil {
		return "", err
	}
	path := filepath.Join(projectDir, "runtime", t.nftName()+".nft")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// LoadNFT 用 nft -f 加载表（同名表先删除，保证幂等）。
func (t *Tunnel) LoadNFT(projectDir string) error {
	path, err := t.WriteNFT(projectDir)
	if err != nil {
		return err
	}
	exec.Command("nft", "delete", "table", "ip6", t.nftName()).Run()
	if out, err := exec.Command("nft", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f %s: %w (%s)", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// TakeoverLegacy 接管所有旧 route64_random* 生产表（route64_random/
// route64_random_2 等）：逐个备份到 backups/ 后删除。
// 否则旧表与程序表同 hook 都会被触发，粘性源地址会被旧 numgen 规则 SNAT。
// isLegacyRandom 判断旧裂变表名：route64 开头且含 random
// （route64_random / route64_random_2 / route64_r1mci_random / route64_r1ash_random ...）
func isLegacyRandom(name string) bool {
	return strings.HasPrefix(name, "route64") && strings.Contains(name, "random")
}

func TakeoverLegacy(projectDir string) error {
	out, err := exec.Command("nft", "list", "tables", "ip6").Output()
	if err != nil {
		return err
	}
	// 提取所有旧裂变表
	var tables []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "table ip6 ") {
			if n := strings.TrimPrefix(line, "table ip6 "); isLegacyRandom(n) {
				tables = append(tables, n)
			}
		}
	}
	if len(tables) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(projectDir, "backups"), 0o755); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	for _, name := range tables {
		list, err := exec.Command("nft", "list", "table", "ip6", name).Output()
		if err != nil {
			return fmt.Errorf("list legacy table %s: %w", name, err)
		}
		bak := filepath.Join(projectDir, "backups", name+"."+ts+".nft")
		if err := os.WriteFile(bak, list, 0o600); err != nil {
			return err
		}
		if _, err := exec.Command("nft", "delete", "table", "ip6", name).CombinedOutput(); err != nil {
			return fmt.Errorf("delete legacy table %s: %w", name, err)
		}
	}
	return nil
}

func sortedMarks(m map[int]netip.Addr) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
