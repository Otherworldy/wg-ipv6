package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		configPath = flag.String("config", "config.yaml", "配置文件路径")
		install    = flag.Bool("install", false, "自动安装缺失的系统包 (apt/dnf)")
		dryRun     = flag.Bool("dry-run", false, "只生成规则与计划，不加载不监听")
		check      = flag.Bool("check", false, "校验配置与规则生成后退出")
		unreg      = flag.String("unregister", "", "删除账号粘性映射后退出")
		skipSystem = flag.Bool("skip-system", false, "冒烟/调试：跳过环境检查与系统规则加载，只起 SOCKS5")
	)
	flag.Parse()
	logger := log.New(os.Stderr, "proxy-sticky: ", log.LstdFlags|log.Lmsgprefix)

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	var tunnels []*Tunnel
	for _, tc := range cfg.Tunnels {
		t, err := parseTunnel(tc)
		if err != nil {
			logger.Fatalf("tunnel: %v", err)
		}
		t.BuildSeedMarks(cfg.SeedAccounts, cfg.SeedMarks)
		tunnels = append(tunnels, t)
	}

	if *check {
		for _, t := range tunnels {
			content, err := t.BuildNFT()
			if err != nil {
				logger.Fatalf("build nft %s: %v", t.Conf.Name, err)
			}
			fmt.Printf("=== %s ===\n", t.Conf.Name)
			for _, line := range strings.Split(content, "\n") {
				if strings.Contains(line, "numgen") {
					fmt.Printf("... numgen random mod %d -> %d addresses ...\n", t.Conf.PoolSize, t.Conf.PoolSize)
					fmt.Println("\t\t}")
					break
				}
				if tr := strings.TrimSpace(line); tr != "" {
					fmt.Println(line)
				}
			}
			fmt.Printf("base=%s prefix=%s pool=%d sticky_start=%s mark=%#x table=%d\n\n",
				t.Base, t.Prefix, t.Conf.PoolSize, t.Conf.StickyStart, t.Conf.Mark, t.Conf.Table)
		}
		return
	}

	if *dryRun {
		fmt.Println("== dry-run: 将写入 runtime/*.nft 并加载 ==")
		for _, t := range tunnels {
			content, _ := t.BuildNFT()
			fmt.Printf("-- %s --\n%s\n", t.nftName(), content)
		}
		fmt.Println("== 计划 ==")
		for _, t := range tunnels {
			fmt.Printf("%s: wg-quick up (接口未运行时); ip -6 rule add pref %d fwmark %#x/0xff lookup %d\n",
				t.Conf.Name, t.rulePref(), t.Conf.Mark, t.Conf.Table)
		}
		fmt.Println("删除旧表 ip6 route64_random (备份至 backups/)")
		return
	}

	if !*skipSystem {
		if err := checkEnv(*install); err != nil {
			logger.Fatalf("%v", err)
		}
	}

	store, err := LoadStore(cfg.StateFile)
	if err != nil {
		logger.Fatalf("state: %v", err)
	}
	if !*skipSystem {
		for username, addrStr := range cfg.SeedAccounts {
			if err := seedAccount(store, tunnels, username, addrStr); err != nil {
				logger.Fatalf("seed %s: %v", username, err)
			}
		}
	}
	if *unreg != "" {
		r, ok := store.Unregister(*unreg)
		if !ok {
			logger.Fatalf("no record for %s", *unreg)
		}
		for _, t := range tunnels {
			if t.Conf.Name == r.Tunnel {
				if addr, err := parseIPv6Addr(r.Addr); err == nil {
					exec.Command("ip", "-6", "addr", "del", addr.String()+"/128", "dev", t.Conf.Name).Run()
				}
			}
		}
		logger.Printf("unregistered %s (%s)", *unreg, r.Addr)
		return
	}

	if !*skipSystem {
		for _, t := range tunnels {
			if _, err := t.WriteNFT(cfg.BaseDir); err != nil {
				logger.Fatalf("write nft %s: %v", t.Conf.Name, err)
			}
		}
		for _, t := range tunnels {
			if err := t.EnsureUp(cfg.BaseDir, cfg.ManageWG); err != nil {
				logger.Fatalf("ensure up %s: %v", t.Conf.Name, err)
			}
		}
		if err := TakeoverLegacy(cfg.BaseDir); err != nil {
			logger.Fatalf("takeover: %v", err)
		}
		for _, t := range tunnels {
			if err := t.EnsureRule(); err != nil {
				logger.Fatalf("rule %s: %v", t.Conf.Name, err)
			}
			if err := t.LoadNFT(cfg.BaseDir); err != nil {
				logger.Fatalf("nft %s: %v", t.Conf.Name, err)
			}
		}
	}

	// 启动清理：删除接口上不属于 base 且不在粘性记录中的 /128
	// （ephemeral 临时地址在进程退出/重启时可能残留，vless 源地址选择会因此绕过 numgen 随机）
	PruneStaleAddrs(tunnels, store)

	srv := NewServer(cfg, store, tunnels, logger)

	// 粘性账号闲置回收：脱敏，跳过 seed 账号
	if cfg.AccountIdleTTL > 0 {
		protected := make(map[string]bool, len(cfg.SeedAccounts))
		for u := range cfg.SeedAccounts {
			protected[u] = true
		}
		go reapLoop(logger, srv, store, tunnels, protected, cfg.AccountIdleTTL)
	}

	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Fatalf("listen %s: %v (sing-box 占用 26183 时请改 listen 或停用其 socks5-in)", cfg.Listen, err)
	}
	logger.Printf("listening %s, default_account=%s, tunnels=%d", cfg.Listen, cfg.DefaultAccount, len(tunnels))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logger.Printf("shutting down")
		l.Close()
		os.Exit(0)
	}()
	if err := srv.Serve(l); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}

// seedAccount 把配置中的 seed 账号写入存储（幂等）。
func seedAccount(store *Store, tunnels []*Tunnel, username, addrStr string) error {
	addr, err := parseIPv6Addr(addrStr)
	if err != nil {
		return err
	}
	for _, t := range tunnels {
		if t.Prefix.Contains(addr) {
			return store.Seed(t, username, addr)
		}
	}
	return fmt.Errorf("no tunnel contains %s", addrStr)
}

// reapLoop 周期性回收闲置粘性账号：删除 state 记录、接口地址并清 ensured 缓存。
func reapLoop(logger *log.Logger, srv *Server, store *Store, tunnels []*Tunnel, protected map[string]bool, ttl time.Duration) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		removed := store.ReapIdle(time.Now(), ttl, protected)
		for _, e := range removed {
			addr, err := netip.ParseAddr(e.Rec.Addr)
			if err != nil {
				continue
			}
			for _, t := range tunnels {
				if t.Conf.Name == e.Rec.Tunnel {
					exec.Command("ip", "-6", "addr", "del", addr.String()+"/128", "dev", t.Conf.Name).Run()
					srv.ForgetAddr(t, addr)
					logger.Printf("idle account reaped: %s (%s)", redact(e.Name), addr)
				}
			}
		}
	}
}

// redact 隐藏账号中的敏感部分（只保留前缀与末 4 字符）。
func redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// PruneStaleAddrs 启动时清理接口上的非基础、不在 state 记录中的 /128 地址。
func PruneStaleAddrs(tunnels []*Tunnel, store *Store) {
	kept := map[string]bool{}
	for _, r := range store.records {
		kept[r.Addr] = true
	}
	for _, t := range tunnels {
		out, _ := exec.Command("ip", "-6", "-o", "addr", "show", "dev", t.Conf.Name).Output()
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || !strings.Contains(f[3], ":") {
				continue
			}
			a := f[3] // 形如 2a11:...::2/64
			addrStr := strings.Split(a, "/")[0]
			if addrStr == t.Base.String() || kept[addrStr] {
				continue
			}
			if _, err := exec.Command("ip", "-6", "addr", "del", a, "dev", t.Conf.Name).CombinedOutput(); err == nil {
				log.Printf("pruned stale addr %s on %s", addrStr, t.Conf.Name)
			}
		}
	}
}
