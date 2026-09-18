package main

import (
	"bytes"
	"encoding/json"
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

func TestOutboundBind(t *testing.T) {
	obtag := outboundOf(map[string]any{"route": map[string]any{"rules": []any{
		map[string]any{"inbound": []any{"vless-route64"}, "outbound": "route64-ipv6"},
	}}}, "vless-route64")
	if obtag != "route64-ipv6" {
		t.Fatalf("outbound %s", obtag)
	}
	o := &obFile{Outbounds: []map[string]any{
		{"tag": "direct"},
		{"tag": "route64-ipv6", "bind_interface": "route64"},
	}}
	if outboundBind(o, "route64-ipv6") != "route64" {
		t.Fatal("bind")
	}
	if outboundBind(o, "direct") != "" {
		t.Fatal("direct")
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
