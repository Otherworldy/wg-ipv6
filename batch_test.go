package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- 测试脚手架 ----

func newSBDir(t *testing.T, cfg *Config) {
	t.Helper()
	cfg.BaseDir = t.TempDir()
	cfg.SingBoxDir = filepath.Join(cfg.BaseDir, "conf")
	if err := os.MkdirAll(cfg.SingBoxDir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeSBFile(t *testing.T, cfg *Config, name string, v any) {
	t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.SingBoxDir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func stubRestart(t *testing.T) {
	t.Helper()
	old := restartSingBox
	oldBin := singboxBin
	restartSingBox = func() error { return nil }
	singboxBin = "/nonexistent/sing-box" // 单元测试不跑真实 check（无证书）
	t.Cleanup(func() {
		restartSingBox = old
		singboxBin = oldBin
	})
}

// vlessInboundSB 建一个含 vless-a / 邻居 vless-a-b 的临时配置，并写 url.txt 模板行。
func vlessInboundSB(t *testing.T, cfg *Config, tmpl string) {
	t.Helper()
	newSBDir(t, cfg)
	writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-a", "type": "vless", "listen_port": 9001,
			"users": []any{map[string]any{"uuid": "orig", "flow": "xtls-rprx-vision"}}},
		map[string]any{"tag": "vless-a-b", "type": "vless", "listen_port": 9002},
	}})
	writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "direct", "type": "direct"},
	}})
	writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{
		"final": "direct", "rules": []any{},
	}})
	if tmpl != "" {
		if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte(tmpl+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

const vlessTmpl = "vless://orig@1.2.3.4:9001?encryption=none&security=reality&sni=www.iij.ad.jp&type=tcp#vless-a"

func bindTunnel(t *testing.T, cfg *Config, inTag, tun string) {
	t.Helper()
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = inb
	if err := attachTunnelOutbound(cfg, ob, rt, inTag, tun); err != nil {
		t.Fatal(err)
	}
	if err := writeSB(cfg.SingBoxDir, inb, ob, rt); err != nil {
		t.Fatal(err)
	}
}

// ---- 规则顺序 ----

// 所有 auth_user 规则必须在入口通用规则之前，否则分流永远不生效
func TestBatchRuleOrder(t *testing.T) {
	stubRestart(t)
	cfg := testCfg()
	vlessInboundSB(t, cfg, vlessTmpl)
	bindTunnel(t, cfg, "vless-a", "route64")
	if _, _, _, err := generateUsers(cfg, "vless-a", 3); err != nil {
		t.Fatal(err)
	}
	_, _, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	plainIdx := -1
	userRules := 0
	for i, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m == nil || !matchInboundTag(m["inbound"], "vless-a") {
			continue
		}
		if len(authUsersOf(m)) == 0 {
			plainIdx = i
			continue
		}
		userRules++
		if plainIdx >= 0 {
			t.Fatalf("auth_user rule at %d after plain rule at %d", i, plainIdx)
		}
	}
	if userRules != 3 || plainIdx < 0 {
		t.Fatalf("userRules=%d plainIdx=%d", userRules, plainIdx)
	}
}

// 「改入口」里点保存（同隧道/换隧道）不能清掉按用户分流的规则，且账号要跟着换隧道
func TestAttachKeepsUserRoutes(t *testing.T) {
	stubRestart(t)
	cfg := testCfg()
	vlessInboundSB(t, cfg, vlessTmpl)
	bindTunnel(t, cfg, "vless-a", "route64")
	if _, _, _, err := generateUsers(cfg, "vless-a", 2); err != nil {
		t.Fatal(err)
	}
	bindTunnel(t, cfg, "vless-a", "route64-sg3")

	_, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	userRules := 0
	for _, r := range routeRules(rt) {
		if m, _ := r.(map[string]any); m != nil && matchInboundTag(m["inbound"], "vless-a") && len(authUsersOf(m)) > 0 {
			userRules++
		}
	}
	if userRules != 2 {
		t.Fatalf("user routes after save: %d", userRules)
	}
	switched := 0
	for _, o := range ob.Outbounds {
		if _, ok := psUserID("vless-a", asString(o["tag"])); !ok {
			continue
		}
		if !strings.HasPrefix(asString(o["username"]), "43b3277e.route64-sg3.vless-a-") {
			t.Fatalf("account not switched: %s", asString(o["username"]))
		}
		switched++
	}
	if switched != 2 {
		t.Fatalf("user outbounds %d", switched)
	}
	// 共享出站也要指向新隧道
	if outboundTunnel(cfg, ob, psOutboundTag("vless-a")) != "route64-sg3" {
		t.Fatal("shared outbound not switched")
	}
}

// 已批量生成过的入口，改 listen 端口后必须被判为「陈旧」并重写（含每用户出站）
func TestEntryOutboundsStale(t *testing.T) {
	stubRestart(t)
	cfg := testCfg()
	vlessInboundSB(t, cfg, vlessTmpl)
	bindTunnel(t, cfg, "vless-a", "route64")
	if _, _, _, err := generateUsers(cfg, "vless-a", 2); err != nil {
		t.Fatal(err)
	}
	_, ob, _, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	if entryOutboundsStale(cfg, ob, "vless-a", "127.0.0.1", 26184) {
		t.Fatal("fresh entry reported stale")
	}
	if !entryOutboundsStale(cfg, ob, "vless-a", "127.0.0.1", 26200) {
		t.Fatal("port change not detected")
	}
}

// ---- 清���与邻居前缀 ----

func TestDropPSOutboundNeighbourTag(t *testing.T) {
	ob := &obFile{Outbounds: []map[string]any{
		{"tag": "ps-vless-a", "type": "socks", "username": "43b3277e.route64.vless-a"},
		{"tag": "psu-vless-a-1234abcd", "type": "socks", "username": "43b3277e.route64.vless-a-1234abcd"},
		{"tag": "psu-vless-a-b-1234abcd", "type": "socks", "username": "43b3277e.route64.vless-a-b-1234abcd"},
		{"tag": "direct", "type": "direct"},
	}}
	dropPSOutbound(ob, "vless-a")
	has := func(tag string) bool { _, o := findInbound(ob.Outbounds, tag); return o != nil }
	if has("ps-vless-a") || has("psu-vless-a-1234abcd") {
		t.Fatal("own outbounds kept")
	}
	if !has("psu-vless-a-b-1234abcd") || !has("direct") {
		t.Fatal("neighbour outbound dropped")
	}

	cfg := testCfg()
	newSBDir(t, cfg)
	writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-a", "type": "vless", "listen_port": 9001},
	}})
	writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": ob.Outbounds})
	writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"vless-a"}, "outbound": "direct"}},
	}})
	for u := range entryAccounts(cfg) {
		if strings.Contains(u, "vless-a-b") {
			t.Fatalf("neighbour account protected: %s", u)
		}
	}
}

// ---- 链接形态 ----

func TestBatchLinkUserinfo(t *testing.T) {
	cases := []string{"trojan", "tuic", "socks"}
	tmpls := map[string]string{
		"trojan": "trojan://oldpass@1.2.3.4:9001?security=tls&sni=x#trojan-a",
		"tuic":   "tuic://olduuid:oldpass@1.2.3.4:9001?congestion_control=bbr#tuic-a",
		"socks":  "",
	}
	for _, typ := range cases {
		stubRestart(t)
		cfg := testCfg()
		newSBDir(t, cfg)
		tag := typ + "-a"
		var users []any
		switch typ {
		case "trojan":
			users = []any{map[string]any{"name": "u", "password": "p"}}
		case "tuic":
			users = []any{map[string]any{"name": "u", "uuid": "olduuid", "password": "p"}}
		case "socks":
			users = []any{map[string]any{"username": "u", "password": "p"}}
		}
		writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{
			map[string]any{"tag": tag, "type": typ, "listen_port": 9001, "users": users},
		}})
		writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": []any{
			map[string]any{"tag": "ps-" + tag, "type": "socks", "server": "127.0.0.1",
				"server_port": 26184, "version": "5", "username": "43b3277e.route64." + tag,
				"password": "pw", "network": "tcp"},
		}})
		writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{
			"final": "direct",
			"rules": []any{map[string]any{"inbound": []any{tag}, "outbound": "ps-" + tag}},
		}})
		line := tmpls[typ]
		if line == "" {
			line = "trojan://x@9.9.9.9:1#x" // url.txt 存在但没有该端口模板
		}
		if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, nodes, err := generateUsers(cfg, tag, 1)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		u, err := url.Parse(nodes[0].URL)
		if err != nil {
			t.Fatalf("%s parse %s: %v", typ, nodes[0].URL, err)
		}
		if u.Fragment != nodes[0].Name {
			t.Fatalf("%s frag %q", typ, u.Fragment)
		}
		switch typ {
		case "trojan":
			if u.User.Username() != nodes[0].Password {
				t.Fatalf("trojan user %q", u.User.Username())
			}
		case "tuic":
			if u.User.Username() != nodes[0].UUID {
				t.Fatalf("tuic user %q", u.User.Username())
			}
			if pw, _ := u.User.Password(); pw != nodes[0].Password {
				t.Fatalf("tuic pass %q", pw)
			}
		case "socks":
			if u.Scheme != "socks5" || u.User.Username() != nodes[0].Username {
				t.Fatalf("socks user %q", u.User.Username())
			}
			if pw, _ := u.User.Password(); pw != nodes[0].Password {
				t.Fatalf("socks pass %q", pw)
			}
		}
	}
}

// url.txt 不存在时：socks 类型要创建文件并写入，vless 缺模板要明确报错
func TestBatchURLTxtHandling(t *testing.T) {
	stubRestart(t)
	cfg := testCfg()
	newSBDir(t, cfg)
	writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "socks-a", "type": "socks", "listen_port": 9100},
	}})
	writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "ps-socks-a", "type": "socks", "server": "127.0.0.1",
			"server_port": 26184, "version": "5", "username": "43b3277e.route64.socks-a",
			"password": "pw", "network": "tcp"},
	}})
	writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"socks-a"}, "outbound": "ps-socks-a"}},
	}})
	// url.txt 里没有主机名时 socks 链接必须报错，而不是静默给 127.0.0.1
	if _, _, _, err := generateUsers(cfg, "socks-a", 1); err == nil {
		t.Fatal("want error when no public host known")
	}
	// 有主机名（任意一行别的入口链接）就可生成，并追加进 url.txt
	if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte("trojan://x@203.0.113.9:9100#x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, nodes, err := generateUsers(cfg, "socks-a", 2)
	if err != nil || len(nodes) != 2 {
		t.Fatalf("socks batch: %v %d", err, len(nodes))
	}
	if !strings.Contains(nodes[0].URL, "203.0.113.9:9100") {
		t.Fatalf("socks url %s", nodes[0].URL)
	}
	if lines := loadURLLines(cfg.SingBoxDir); len(lines) != 3 {
		t.Fatalf("url.txt lines %d", len(lines))
	}

	// vless 缺模板要明确报错（不落盘）
	cfg2 := testCfg()
	vlessInboundSB(t, cfg2, "")
	os.Remove(urlTxtPath(cfg2.SingBoxDir))
	if _, _, _, err := generateUsers(cfg2, "vless-a", 1); err == nil {
		t.Fatal("want error when template missing")
	}

	// vmess 无需模板（buildVmessURL 兜底）：url.txt 不存在时也要被创建
	cfg3 := testCfg()
	newSBDir(t, cfg3)
	writeSBFile(t, cfg3, "inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "vmess-a", "type": "vmess", "listen_port": 9200,
			"users": []any{map[string]any{"uuid": "olduuid"}}},
	}})
	writeSBFile(t, cfg3, "outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "ps-vmess-a", "type": "socks", "server": "127.0.0.1",
			"server_port": 26184, "version": "5", "username": "43b3277e.route64.vmess-a",
			"password": "pw", "network": "tcp"},
	}})
	writeSBFile(t, cfg3, "route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"vmess-a"}, "outbound": "ps-vmess-a"}},
	}})
	if _, _, nodes, err := generateUsers(cfg3, "vmess-a", 2); err != nil || len(nodes) != 2 {
		t.Fatalf("vmess batch: %v %d", err, len(nodes))
	}
	if lines := loadURLLines(cfg3.SingBoxDir); len(lines) != 2 {
		t.Fatalf("url.txt not created: %d", len(lines))
	}
}

// 改端口：同端口所有行（含批量节点）换端口，凭据/备注保留，别的端口不动
func TestUpsertShareURLRewritesAllLines(t *testing.T) {
	cfg := testCfg()
	newSBDir(t, cfg)
	lines := []string{
		"vless://uuid-entry@1.2.3.4:9001?security=reality#vless-a",
		"vless://uuid-node1@1.2.3.4:9001?security=reality#vless-a-11112222",
		"vless://uuid-other@1.2.3.4:9002?security=reality#vless-b",
	}
	if err := saveURLLines(cfg.SingBoxDir, lines); err != nil {
		t.Fatal(err)
	}
	ib := map[string]any{"tag": "vless-a", "users": []any{map[string]any{"uuid": "uuid-entry"}}}
	upsertShareURL(cfg.SingBoxDir, 9001, 9500, ib, 0)
	got := loadURLLines(cfg.SingBoxDir)
	if len(got) != 3 {
		t.Fatalf("lines %d", len(got))
	}
	if sharePort(got[0]) != 9500 || sharePort(got[1]) != 9500 {
		t.Fatalf("ports %s / %s", got[0], got[1])
	}
	if sharePort(got[2]) != 9002 {
		t.Fatal("unrelated line changed")
	}
	if !strings.Contains(got[1], "uuid-node1") || !strings.Contains(got[1], "vless-a-11112222") {
		t.Fatalf("node creds lost: %s", got[1])
	}
}

// 顶层凭据与 users[] 互斥：批量后要清掉顶层字段
func TestBatchDropsTopLevelCreds(t *testing.T) {
	stubRestart(t)
	cfg := testCfg()
	newSBDir(t, cfg)
	writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{
		map[string]any{"tag": "hy2-a", "type": "hysteria2", "listen_port": 9101,
			"password": "toplevel",
			"users":    []any{map[string]any{"name": "u", "password": "toplevel"}}},
	}})
	writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "ps-hy2-a", "type": "socks", "server": "127.0.0.1",
			"server_port": 26184, "version": "5", "username": "43b3277e.route64.hy2-a",
			"password": "pw", "network": "tcp"},
	}})
	writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{
		"final": "direct",
		"rules": []any{map[string]any{"inbound": []any{"hy2-a"}, "outbound": "ps-hy2-a"}},
	}})
	if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte("hysteria2://old@1.2.3.4:9101?sni=x#hy2-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := generateUsers(cfg, "hy2-a", 1); err != nil {
		t.Fatal(err)
	}
	inb, _, _, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	_, ib := findInbound(inb.Inbounds, "hy2-a")
	if _, ok := ib["password"]; ok {
		t.Fatal("top-level password kept alongside users[]")
	}
}

// 从零创建 socks 入口（POST /api/inbounds {"type":"socks"}）
func TestAddSocksInbound(t *testing.T) {
	cfg := testCfg()
	newSBDir(t, cfg)
	stubRestart(t)
	writeSBFile(t, cfg, "inbounds.json", map[string]any{"inbounds": []any{}})
	writeSBFile(t, cfg, "outbounds.json", map[string]any{"outbounds": []any{
		map[string]any{"tag": "direct", "type": "direct"},
	}})
	writeSBFile(t, cfg, "route.json", map[string]any{"route": map[string]any{"final": "direct"}})
	if err := os.WriteFile(urlTxtPath(cfg.SingBoxDir), []byte("vless://x@203.0.113.9:61367#a"+string(rune(10))), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &admin{cfg: cfg, log: log.New(io.Discard, "", 0)}
	body := `{"type":"socks","tag":"socks-hw","listen_port":61369,"tunnel":"route64"}`
	w := httptest.NewRecorder()
	a.addInbound(w, httptest.NewRequest("POST", "/api/inbounds", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("addInbound %d %s", w.Code, w.Body.String())
	}
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		t.Fatal(err)
	}
	_, ib := findInbound(inb.Inbounds, "socks-hw")
	if ib == nil {
		t.Fatal("socks inbound missing")
	}
	users, _ := ib["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("users %d", len(users))
	}
	u, _ := users[0].(map[string]any)
	if asString(u["username"]) != "socks-hw" || asString(u["password"]) == "" {
		t.Fatalf("user %+v", u)
	}
	shared := 0
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) == psOutboundTag("socks-hw") {
			shared++
		}
	}
	if shared != 1 {
		t.Fatalf("shared outbound count %d", shared)
	}
	if n := len(loadURLLines(cfg.SingBoxDir)); n != 2 {
		t.Fatalf("url.txt lines %d", n)
	}
	// 批量 2 个 socks 节点：用户名唯一，且 auth_user 规则指向各自的 psu- 出站
	kind, tun, nodes, err := generateUsers(cfg, "socks-hw", 2)
	if err != nil || kind != "userpass" || tun != "route64" || len(nodes) != 2 {
		t.Fatalf("batch: %v %s %s %d", err, kind, tun, len(nodes))
	}
	inb, _, rt, _ = loadSB(cfg.SingBoxDir)
	if _, ib = findInbound(inb.Inbounds, "socks-hw"); ib == nil {
		t.Fatal("socks inbound gone")
	}
	if got := len(ib["users"].([]any)); got != 3 {
		t.Fatalf("users after batch %d", got)
	}
	seen := map[string]bool{}
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m == nil || len(authUsersOf(m)) == 0 {
			continue
		}
		for _, x := range authUsersOf(m) {
			seen[asString(x)] = true
		}
	}
	for _, n := range nodes {
		if !seen[n.Username] {
			t.Fatalf("no auth_user rule for %s", n.Username)
		}
	}
}
