package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type (
	Config struct {
		Listen         string            `yaml:"listen"`
		Password       string            `yaml:"password"`
		DefaultAccount string            `yaml:"default_account"`
		DefaultTunnel  string            `yaml:"default_tunnel"`
		ManageWG       bool              `yaml:"manage_wg"`
		Tunnels        []TunnelConf      `yaml:"tunnels"`
		SeedAccounts   map[string]string `yaml:"seed_accounts"`
		SeedMarks      map[string]int    `yaml:"seed_marks"` // 旧 sing-box 兼容 mark -> 固定 SNAT
		StateFile      string            `yaml:"state_file"`
		MaxConns       int               `yaml:"max_conns"`
		ConnectTimeout time.Duration     `yaml:"connect_timeout"`
		IdleTimeout    time.Duration     `yaml:"idle_timeout"`
		AccountIdleTTL time.Duration     `yaml:"account_idle_ttl"` // 粘性账号闲置回收（0=禁用）
		LogLevel       string            `yaml:"log_level"`
		BaseDir        string            `yaml:"-"`
	}

	TunnelConf struct {
		Name        string `yaml:"name"`
		WGConf      string `yaml:"wg_conf"`
		Table       int    `yaml:"table"`
		Mark        int    `yaml:"mark"`
		PoolSize    int    `yaml:"pool_size"`
		PoolStart   string `yaml:"pool_start"`
		StickyStart string `yaml:"sticky_start"`
	}
)

// LoadConfig 读取并校验配置，相对路径以配置文件所在目录解析。
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	c.BaseDir = base
	if c.StateFile != "" && !filepath.IsAbs(c.StateFile) {
		c.StateFile = filepath.Join(base, c.StateFile)
	}
	// 默认值
	if c.Listen == "" {
		c.Listen = ":26184"
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 4096
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.IdleTimeout < 0 {
		c.IdleTimeout = 0
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Mark == 0 {
			t.Mark = 0x40 + i
		}
		if t.Table == 0 {
			t.Table = 64 + i
		}
		if t.PoolSize == 0 {
			t.PoolSize = 4096
		}
		if t.PoolStart == "" {
			t.PoolStart = "::10"
		}
		if t.StickyStart == "" {
			t.StickyStart = "::2000"
		}
	}
	if err := c.validate(base); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate(base string) error {
	if c.Password == "" || c.Password == "CHANGE_ME" {
		return fmt.Errorf("config: password must be set")
	}
	if c.DefaultAccount == "" {
		return fmt.Errorf("config: default_account required")
	}
	if len(c.Tunnels) == 0 {
		return fmt.Errorf("config: at least one tunnel required")
	}
	if c.DefaultTunnel == "" {
		c.DefaultTunnel = c.Tunnels[0].Name
	}
	seen := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Name == "" || t.WGConf == "" {
			return fmt.Errorf("tunnels[%d]: name and wg_conf required", i)
		}
		if seen[t.Name] {
			return fmt.Errorf("tunnels: duplicate name %q", t.Name)
		}
		seen[t.Name] = true
		if !filepath.IsAbs(t.WGConf) {
			t.WGConf = filepath.Join(base, t.WGConf)
		}
	}
	if !seen[c.DefaultTunnel] {
		return fmt.Errorf("default_tunnel %q not found in tunnels", c.DefaultTunnel)
	}
	return nil
}

// IID 工具：地址低 64 位与组装。
func iidOf(a netip.Addr) uint64 {
	b := a.As16()
	return beUint64(b[8:])
}

func addrFromIID(prefix netip.Prefix, iid uint64) netip.Addr {
	b := prefix.Addr().As16()
	bePutUint64(b[8:], iid)
	return netip.AddrFrom16(b)
}

func beUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func bePutUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func parseIPv6Addr(s string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(s))
}
