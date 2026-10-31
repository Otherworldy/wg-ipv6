package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeName(t *testing.T) {
	if _, err := sanitizeName("route64-r2ash"); err != nil {
		t.Fatal(err)
	}
	if _, err := sanitizeName("all"); err == nil {
		t.Fatal("reserved")
	}
	if _, err := sanitizeName("-bad"); err == nil {
		t.Fatal("leading dash")
	}
}

func TestNextTableMark(t *testing.T) {
	table, mark := nextTableMark([]TunnelConf{
		{Table: 64, Mark: 0x40},
		{Table: 67, Mark: 0x43},
	})
	if table != 68 || mark != 0x44 {
		t.Fatalf("got %d %#x", table, mark)
	}
}

func TestYAMLPreservesDuration(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	raw := []byte("listen: \":1\"\npassword: x\ndefault_account: a\ndefault_tunnel: route64\naccount_idle_ttl: 720h\nephemeral_grace: 60s\nidle_timeout: 10m\nconnect_timeout: 15s\ntunnels:\n  - name: route64\n    wg_conf: wg/route64.conf\n    table: 64\n    mark: 0x40\n")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	doc, err := loadYAMLDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	m := rootMap(doc)
	if err := yamlAppendTunnel(m, TunnelConf{Name: "route64-b", Table: 65, Mark: 0x41, PoolSize: 240, PoolStart: "::10", StickyStart: "::2000"}); err != nil {
		t.Fatal(err)
	}
	if err := writeYAMLDoc(p, doc); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(p)
	s := string(out)
	for _, want := range []string{"720h", "60s", "10m", "15s", "route64-b", "0x41"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestValidateWGConf(t *testing.T) {
	conf := "[Interface]\nAddress = 2a11:6c7:f33:bb::2/64\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n[Peer]\nPublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\nEndpoint = 1.2.3.4:9\nAllowedIPs = ::/0\n"
	p, err := validateWGConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "2a11:6c7:f33:bb::2/64" {
		t.Fatalf("prefix %s", p)
	}
	if _, err := validateWGConf("[Interface]\nAddress = 1.2.3.4/32\n"); err == nil {
		t.Fatal("expected fail")
	}
}

func TestSessCookie(t *testing.T) {
	tok := makeSess("secret")
	if !validSess("secret", tok) {
		t.Fatal("valid")
	}
	if validSess("other", tok) {
		t.Fatal("wrong pass")
	}
	if checkPass("a", "b") {
		t.Fatal("checkPass")
	}
	if !checkPass("x", "x") {
		t.Fatal("equal")
	}
}

func TestAdminLogin(t *testing.T) {
	a := &admin{cfg: &Config{AdminPassword: "s3cret", AdminListen: "127.0.0.1:0"}}
	ts := httptest.NewServer(a.wrap(a.routes()))
	defer ts.Close()
	res, err := http.Post(ts.URL+"/api/login", "application/json", bytes.NewBufferString(`{"password":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("want 403 got %d", res.StatusCode)
	}
	res, err = http.Post(ts.URL+"/api/login", "application/json", bytes.NewBufferString(`{"password":"s3cret"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("login %d", res.StatusCode)
	}
	var ck *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == cookieName {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("no cookie")
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/status", nil)
	req.AddCookie(ck)
	res2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != 200 {
		t.Fatalf("status %d", res2.StatusCode)
	}
	var st map[string]any
	json.NewDecoder(res2.Body).Decode(&st)
	if _, ok := st["socks"]; !ok {
		t.Fatalf("status %+v", st)
	}
}

func testCfg() *Config {
	return &Config{
		Listen: "0.0.0.0:26184", Password: "pw", DefaultAccount: "43b3277e", DefaultTunnel: "route64",
		Tunnels: []TunnelConf{{Name: "route64"}, {Name: "route64-sg3"}},
	}
}

func TestAttachTunnelOutbound(t *testing.T) {
	cfg := testCfg()
	ob := &obFile{Outbounds: []map[string]any{
		{"tag": "direct", "type": "direct"},
		{"tag": "wg-route64-sg3", "type": "direct", "bind_interface": "route64-sg3"},
	}}
	rt := map[string]any{"route": map[string]any{"final": "direct", "rules": []any{
		map[string]any{"inbound": []any{"vless-x"}, "outbound": "wg-route64-sg3"},
	}}}
	if err := attachTunnelOutbound(cfg, ob, rt, "vless-x", "route64-sg3"); err != nil {
		t.Fatal(err)
	}
	if got := outboundOf(rt, "vless-x"); got != "ps-vless-x" {
		t.Fatalf("route outbound %s", got)
	}
	if outboundTunnel(cfg, ob, "ps-vless-x") != "route64-sg3" {
		t.Fatalf("tunnel %s", outboundTunnel(cfg, ob, "ps-vless-x"))
	}
	if outboundTunnel(cfg, ob, "direct") != "" {
		t.Fatal("direct must have no tunnel")
	}
	// 旧 direct+bind_interface 出站已无引用，应被清掉；direct 保留
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) == "wg-route64-sg3" {
			t.Fatal("legacy outbound not pruned")
		}
	}
	i, nb := findInbound(ob.Outbounds, "ps-vless-x")
	if i < 0 {
		t.Fatal("no ps outbound")
	}
	if asString(nb["type"]) != "socks" || asString(nb["server"]) != "127.0.0.1" || asInt(nb["server_port"]) != 26184 {
		t.Fatalf("outbound %+v", nb)
	}
	if asString(nb["username"]) != psAccount(cfg, "route64-sg3", "vless-x") || asString(nb["password"]) != "pw" {
		t.Fatalf("creds %+v", nb)
	}
}

// 入口账号必须被 proxy-sticky 解析成「指定隧道的粘性账号」
func TestPSAccountIsStickyOnTunnel(t *testing.T) {
	cfg := testCfg()
	s := &Server{cfg: cfg, tunnels: map[string]*Tunnel{
		"route64":     {Conf: TunnelConf{Name: "route64"}},
		"route64-sg3": {Conf: TunnelConf{Name: "route64-sg3"}},
	}}
	s.defTun = s.tunnels["route64"]
	acc, err := s.parseAccount(psAccount(cfg, "route64-sg3", "vless-ws-cdn"))
	if err != nil {
		t.Fatal(err)
	}
	if !acc.sticky || acc.tun.Conf.Name != "route64-sg3" || acc.name != psAccount(cfg, "route64-sg3", "vless-ws-cdn") {
		t.Fatalf("account %+v", acc)
	}
}

func TestStripTunnelDropsPSOutbounds(t *testing.T) {
	cfg := testCfg()
	ob := &obFile{Outbounds: []map[string]any{{"tag": "direct", "type": "direct"}}}
	rt := map[string]any{"route": map[string]any{"rules": []any{}}}
	inb := &inbFile{}
	for _, tag := range []string{"a", "b"} {
		inb.Inbounds = append(inb.Inbounds, map[string]any{"tag": tag})
		if err := attachTunnelOutbound(cfg, ob, rt, tag, "route64"); err != nil {
			t.Fatal(err)
		}
	}
	disabled := &inbFile{}
	moved := stripTunnelFromSB(cfg, inb, ob, rt, "route64", disabled)
	if len(moved) != 2 || len(disabled.Inbounds) != 2 || len(inb.Inbounds) != 0 {
		t.Fatalf("moved=%v disabled=%d left=%d", moved, len(disabled.Inbounds), len(inb.Inbounds))
	}
	if _, nb := findInbound(ob.Outbounds, "ps-a"); nb != nil {
		t.Fatal("ps outbound kept after tunnel removal")
	}
}

func TestSharePort(t *testing.T) {
	line := "vless://uuid-here@185.93.71.209:55266?encryption=none&security=reality&type=tcp#vless-route64"
	if sharePort(line) != 55266 {
		t.Fatalf("port %d", sharePort(line))
	}
	out := setSharePortAndUser(line, 55270, "new-uuid", "", "vless-x")
	if sharePort(out) != 55270 || !strings.Contains(out, "new-uuid") || !strings.Contains(out, "vless-x") {
		t.Fatalf("out %s", out)
	}
}

func TestPSSocksAddr(t *testing.T) {
	cases := []struct {
		listen, host string
		port         int
		bad          bool
	}{
		{"0.0.0.0:26184", "127.0.0.1", 26184, false},
		{":26184", "127.0.0.1", 26184, false},
		{"[::]:26184", "::1", 26184, false},
		{"10.0.0.5:1234", "10.0.0.5", 1234, false},
		{"127.0.0.1:70000", "", 0, true},
		{"nonsense", "", 0, true},
	}
	for _, c := range cases {
		host, port, err := psSocksAddr(&Config{Listen: c.listen})
		if c.bad {
			if err == nil {
				t.Fatalf("%s: want error", c.listen)
			}
			continue
		}
		if err != nil || host != c.host || port != c.port {
			t.Fatalf("%s: got %s:%d %v", c.listen, host, port, err)
		}
	}
}

// 仍被引用的旧出站不能被剪掉；本程序没生成过的出站不碰
func TestPruneKeepsReferencedOutbounds(t *testing.T) {
	ob := &obFile{Outbounds: []map[string]any{
		{"tag": "direct", "type": "direct"},
		{"tag": "wg-final", "type": "direct", "bind_interface": "final"},
		{"tag": "wg-set", "type": "direct", "bind_interface": "set"},
		{"tag": "wg-dead", "type": "direct", "bind_interface": "dead"},
		{"tag": "hand-made", "type": "direct", "bind_interface": "whatever"},
	}}
	rt := map[string]any{"route": map[string]any{
		"final": "wg-final",
		"rule_set": []any{
			map[string]any{"tag": "x", "download_detour": "wg-set"},
		},
		"rules": []any{},
	}}
	pruneTunnelOutbounds(ob, rt)
	has := func(tag string) bool { _, o := findInbound(ob.Outbounds, tag); return o != nil }
	for _, tag := range []string{"direct", "wg-final", "wg-set", "hand-made"} {
		if !has(tag) {
			t.Fatalf("%s dropped", tag)
		}
	}
	if has("wg-dead") {
		t.Fatal("unused legacy outbound kept")
	}
}

func TestDropPSOutbound(t *testing.T) {
	ob := &obFile{Outbounds: []map[string]any{
		{"tag": "direct", "type": "direct"},
		{"tag": "ps-a", "type": "socks"},
	}}
	dropPSOutbound(ob, "a")
	if _, o := findInbound(ob.Outbounds, "ps-a"); o != nil {
		t.Fatal("ps outbound kept")
	}
	if _, o := findInbound(ob.Outbounds, "direct"); o == nil {
		t.Fatal("direct dropped")
	}
}

// syncEntryOutbounds：旧出站改写为 socks 回链、二次调用幂等、listen 端口变化会刷新
func TestSyncEntryOutbounds(t *testing.T) {
	old := restartSingBox
	restartSingBox = func() error { return nil }
	defer func() { restartSingBox = old }()

	dir := t.TempDir()
	cfg := testCfg()
	cfg.BaseDir = dir
	cfg.SingBoxDir = filepath.Join(dir, "conf")
	if err := os.MkdirAll(cfg.SingBoxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(filepath.Join(cfg.SingBoxDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-a", "type": "vless", "listen_port": 9001},
	}})
	write("outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "direct", "type": "direct"},
		map[string]any{"tag": "wg-route64", "type": "direct", "bind_interface": "route64"},
	}})
	write("route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"vless-a"}, "outbound": "wg-route64"}},
	}})

	logger := log.New(io.Discard, "", 0)
	if err := syncEntryOutbounds(cfg, logger); err != nil {
		t.Fatal(err)
	}
	_, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := outboundOf(rt, "vless-a"); got != "ps-vless-a" {
		t.Fatalf("outbound %s", got)
	}
	if !psOutboundMatches(ob, "ps-vless-a", "127.0.0.1", 26184) {
		t.Fatal("outbound not pointing at listen")
	}
	if accounts := entryAccounts(cfg); !accounts["43b3277e.route64.vless-a"] {
		t.Fatalf("entry account not protected: %v", accounts)
	}
	// 幂等：没有改动就不重启
	called := false
	restartSingBox = func() error { called = true; return nil }
	if err := syncEntryOutbounds(cfg, logger); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("restart on no-op sync")
	}
	// listen 端口变化 -> 重写出站
	cfg.Listen = "0.0.0.0:26200"
	restartSingBox = func() error { return nil }
	if err := syncEntryOutbounds(cfg, logger); err != nil {
		t.Fatal(err)
	}
	if _, ob, _, _ := loadSB(cfg.SingBoxDir); !psOutboundMatches(ob, "ps-vless-a", "127.0.0.1", 26200) {
		t.Fatal("port not refreshed")
	}
}

func TestUserKind(t *testing.T) {
	for typ, want := range map[string]string{
		"vless": "uuid", "vmess": "uuid", "tuic": "uuidpass",
		"trojan": "pass", "hysteria2": "pass", "anytls": "pass", "socks": "userpass",
	} {
		got, ok := userKind(typ)
		if !ok || got != want {
			t.Fatalf("%s -> %s %v", typ, got, ok)
		}
	}
	if _, ok := userKind("shadowsocks"); ok {
		t.Fatal("shadowsocks should be unsupported")
	}
}

// 批量生成：每个节点独立账号/出站/auth_user 规则，url.txt 追加 N 行，二次生成不互相覆盖
func TestGenerateUsers(t *testing.T) {
	old := restartSingBox
	restartSingBox = func() error { return nil }
	defer func() { restartSingBox = old }()

	dir := t.TempDir()
	cfg := testCfg()
	cfg.BaseDir = dir
	cfg.SingBoxDir = filepath.Join(dir, "conf")
	if err := os.MkdirAll(cfg.SingBoxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(filepath.Join(cfg.SingBoxDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-x", "type": "vless", "listen_port": 9001,
			"users": []any{map[string]any{"uuid": "orig", "flow": "xtls-rprx-vision"}}},
	}})
	write("outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "direct", "type": "direct"},
		map[string]any{"tag": "ps-vless-x", "type": "socks", "server": "127.0.0.1",
			"server_port": 26184, "version": "5", "username": "43b3277e.route64.vless-x",
			"password": "pw", "network": "tcp"},
	}})
	write("route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"vless-x"}, "outbound": "ps-vless-x"}},
	}})
	// url.txt 在 SingBoxDir 的父目录
	tmpl := "vless://orig@1.2.3.4:9001?encryption=none&security=reality&sni=www.iij.ad.jp&type=tcp#vless-x"
	if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte(tmpl+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	kind, tun, nodes, err := generateUsers(cfg, "vless-x", 3)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "uuid" || tun != "route64" || len(nodes) != 3 {
		t.Fatalf("kind=%s tun=%s n=%d", kind, tun, len(nodes))
	}
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	_, ib := findInbound(inb.Inbounds, "vless-x")
	users, _ := ib["users"].([]any)
	if len(users) != 4 { // 1 原有 + 3 新增
		t.Fatalf("users %d", len(users))
	}
	for _, n := range nodes {
		if n.UUID == "" || n.URL == "" || !strings.Contains(n.URL, n.UUID) || !strings.Contains(n.URL, n.Name) {
			t.Fatalf("node %+v", n)
		}
		obTag := psUserOutboundTag("vless-x", n.ID)
		if !psOutboundMatches(ob, obTag, "127.0.0.1", 26184) {
			t.Fatalf("outbound missing for %s", n.ID)
		}
		// 规则：auth_user = 节点 name，出站指向该节点出站
		found := false
		for _, r := range routeRules(rt) {
			m, _ := r.(map[string]any)
			if m != nil && matchInboundTag(m["auth_user"], n.Name) && asString(m["outbound"]) == obTag {
				found = true
			}
		}
		if !found {
			t.Fatalf("no auth_user rule for %s", n.Name)
		}
	}
	// 新增账号必须被入口账号保护（不被闲置回收）
	accounts := entryAccounts(cfg)
	for _, n := range nodes {
		if !accounts[n.Account] {
			t.Fatalf("account not protected: %s", n.Account)
		}
	}
	// url.txt 追加了 3 行
	if lines := loadURLLines(cfg.SingBoxDir); len(lines) != 4 {
		t.Fatalf("url.txt lines %d", len(lines))
	}
	// 第二次生成：不覆盖上一次的规则/出站
	if _, _, more, err := generateUsers(cfg, "vless-x", 2); err != nil || len(more) != 2 {
		t.Fatalf("second batch: %v %d", err, len(more))
	}
	ob2, rt2 := func() (*obFile, map[string]any) {
		_, o, r, e := loadSB(cfg.SingBoxDir)
		if e != nil {
			t.Fatal(e)
		}
		return o, r
	}()
	for _, n := range nodes {
		if !psOutboundMatches(ob2, psUserOutboundTag("vless-x", n.ID), "127.0.0.1", 26184) {
			t.Fatalf("first batch outbound lost: %s", n.ID)
		}
	}
	if got := len(routeRules(rt2)); got != 1+3+2 {
		t.Fatalf("rules %d", got)
	}
}

// 未绑定出口的入口拒绝批量生成（否则节点没有独立地址）
func TestGenerateUsersNeedsTunnel(t *testing.T) {
	old := restartSingBox
	restartSingBox = func() error { return nil }
	defer func() { restartSingBox = old }()

	dir := t.TempDir()
	cfg := testCfg()
	cfg.BaseDir = dir
	cfg.SingBoxDir = filepath.Join(dir, "conf")
	os.MkdirAll(cfg.SingBoxDir, 0o755)
	write := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		os.WriteFile(filepath.Join(cfg.SingBoxDir, name), b, 0o644)
	}
	write("inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-y", "type": "vless", "listen_port": 9002},
	}})
	write("outbounds.json", map[string]any{"outbounds": []any{map[string]any{"tag": "direct", "type": "direct"}}})
	write("route.json", map[string]any{"route": map[string]any{"final": "direct", "rules": []any{}}})
	if _, _, _, err := generateUsers(cfg, "vless-y", 1); err == nil {
		t.Fatal("want error for unbound inbound")
	}
}
