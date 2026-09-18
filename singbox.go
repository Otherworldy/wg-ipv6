package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type inbFile struct {
	Inbounds []map[string]any `json:"inbounds"`
}

type obFile struct {
	Outbounds []map[string]any `json:"outbounds"`
}

var (
	singboxBin = "/etc/sing-box/sing-box"
	restartSingBox = func() error {
		return exec.Command("systemctl", "restart", "sing-box").Run()
	}
)

func loadJSONFile(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func loadSB(dir string) (*inbFile, *obFile, map[string]any, error) {
	inb := &inbFile{}
	ob := &obFile{}
	rt := map[string]any{}
	if err := loadJSONFile(filepath.Join(dir, "inbounds.json"), inb); err != nil {
		return nil, nil, nil, err
	}
	if err := loadJSONFile(filepath.Join(dir, "outbounds.json"), ob); err != nil {
		return nil, nil, nil, err
	}
	if err := loadJSONFile(filepath.Join(dir, "route.json"), &rt); err != nil {
		return nil, nil, nil, err
	}
	return inb, ob, rt, nil
}

func writeSB(dir string, inb *inbFile, ob *obFile, rt map[string]any) error {
	if err := writeJSONFile(filepath.Join(dir, "inbounds.json"), inb); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "outbounds.json"), ob); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(dir, "route.json"), rt)
}

func checkSB(dir string) error {
	if _, err := os.Stat(singboxBin); err != nil {
		return nil
	}
	out, err := exec.Command(singboxBin, "check", "-C", dir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check: %s", bytes.TrimSpace(out))
	}
	return nil
}

func applySingBox(dir string, mut func(inb *inbFile, ob *obFile, rt map[string]any) error) error {
	inb, ob, rt, err := loadSB(dir)
	if err != nil {
		return err
	}
	if err := mut(inb, ob, rt); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "sb-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := exec.Command("cp", "-a", dir+"/.", tmp).Run(); err != nil {
		return fmt.Errorf("copy conf: %w", err)
	}
	if err := writeSB(tmp, inb, ob, rt); err != nil {
		return err
	}
	if err := checkSB(tmp); err != nil {
		return err
	}
	if err := writeSB(dir, inb, ob, rt); err != nil {
		return err
	}
	return restartSingBox()
}

func disabledPath(cfg *Config) string {
	return filepath.Join(cfg.BaseDir, "state", "inbounds-disabled.json")
}

func loadDisabled(cfg *Config) *inbFile {
	f := &inbFile{}
	_ = loadJSONFile(disabledPath(cfg), f)
	if f.Inbounds == nil {
		f.Inbounds = []map[string]any{}
	}
	return f
}

func saveDisabled(cfg *Config, f *inbFile) error {
	if err := os.MkdirAll(filepath.Dir(disabledPath(cfg)), 0o755); err != nil {
		return err
	}
	return writeJSONFile(disabledPath(cfg), f)
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprint(t)
	}
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func deepCopyMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func findInbound(list []map[string]any, tag string) (int, map[string]any) {
	for i, ib := range list {
		if asString(ib["tag"]) == tag {
			return i, ib
		}
	}
	return -1, nil
}

func refreshCreds(ib map[string]any) (uuid, password string) {
	uuid, password = newUUID(), randPassword(16)
	if users, ok := ib["users"].([]any); ok {
		for _, u := range users {
			m, ok := u.(map[string]any)
			if !ok {
				continue
			}
			if _, ok := m["uuid"]; ok {
				m["uuid"] = uuid
			}
			if _, ok := m["password"]; ok {
				m["password"] = password
			}
		}
	}
	if _, ok := ib["password"]; ok {
		ib["password"] = password
	}
	return
}

func routeRules(rt map[string]any) []any {
	r, _ := rt["route"].(map[string]any)
	if r == nil {
		return nil
	}
	rules, _ := r["rules"].([]any)
	return rules
}

func setRouteRules(rt map[string]any, rules []any) {
	r, _ := rt["route"].(map[string]any)
	if r == nil {
		r = map[string]any{}
		rt["route"] = r
	}
	r["rules"] = rules
}

func matchInboundTag(inb any, tag string) bool {
	switch v := inb.(type) {
	case string:
		return v == tag
	case []any:
		for _, x := range v {
			if asString(x) == tag {
				return true
			}
		}
	}
	return false
}

func outboundBind(ob *obFile, obTag string) string {
	if ob == nil || obTag == "" || obTag == "direct" {
		return ""
	}
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) == obTag {
			return asString(o["bind_interface"])
		}
	}
	return ""
}

func outboundOf(rt map[string]any, tag string) string {
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m == nil {
			continue
		}
		if matchInboundTag(m["inbound"], tag) {
			if s := asString(m["outbound"]); s != "" {
				return s
			}
		}
	}
	return "direct"
}

func prependRoute(rt map[string]any, tag, outbound string) {
	rule := map[string]any{"inbound": []any{tag}, "outbound": outbound}
	setRouteRules(rt, append([]any{rule}, routeRules(rt)...))
}

func removeRoutesForInbound(rt map[string]any, tag string) {
	var keep []any
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m != nil && matchInboundTag(m["inbound"], tag) {
			continue
		}
		keep = append(keep, r)
	}
	setRouteRules(rt, keep)
}

func removeRoutesForOutbound(rt map[string]any, obTags map[string]bool) {
	var keep []any
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m != nil && obTags[asString(m["outbound"])] {
			continue
		}
		keep = append(keep, r)
	}
	setRouteRules(rt, keep)
}

func attachTunnelOutbound(ob *obFile, rt map[string]any, inTag, tun string, mark int) string {
	obTag := "wg-" + tun
	found := false
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) == obTag {
			found = true
			break
		}
	}
	if !found {
		ob.Outbounds = append(ob.Outbounds, map[string]any{
			"type":             "direct",
			"tag":              obTag,
			"domain_strategy":  "ipv6_only",
			"bind_interface":   tun,
			"routing_mark":     mark,
		})
	}
	removeRoutesForInbound(rt, inTag)
	prependRoute(rt, inTag, obTag)
	return obTag
}

func stripTunnelFromSB(inb *inbFile, ob *obFile, rt map[string]any, tun string, disabled *inbFile) []string {
	dropOB := map[string]bool{}
	var keepOB []map[string]any
	for _, o := range ob.Outbounds {
		if asString(o["bind_interface"]) == tun {
			dropOB[asString(o["tag"])] = true
			continue
		}
		keepOB = append(keepOB, o)
	}
	ob.Outbounds = keepOB
	var moved []string
	var keepIn []map[string]any
	for _, ib := range inb.Inbounds {
		tag := asString(ib["tag"])
		if dropOB[outboundOf(rt, tag)] {
			disabled.Inbounds = append(disabled.Inbounds, ib)
			moved = append(moved, tag)
			continue
		}
		keepIn = append(keepIn, ib)
	}
	inb.Inbounds = keepIn
	removeRoutesForOutbound(rt, dropOB)
	return moved
}

func publicHost(sbDir string) string {
	p := filepath.Join(filepath.Dir(sbDir), "url.txt")
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		u, err := url.Parse(strings.TrimSpace(line))
		if err != nil || u.Hostname() == "" {
			continue
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.To4() != nil {
			return u.Hostname()
		}
		if !strings.Contains(u.Hostname(), ":") {
			return u.Hostname()
		}
	}
	return ""
}

func urlTxtPath(sbDir string) string {
	return filepath.Join(filepath.Dir(sbDir), "url.txt")
}

func loadURLLines(sbDir string) []string {
	b, err := os.ReadFile(urlTxtPath(sbDir))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func saveURLLines(sbDir string, lines []string) error {
	p := urlTxtPath(sbDir)
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	return os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func sharePort(line string) int {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return 0
	}
	if strings.HasPrefix(line, "vmess://") {
		raw := strings.TrimPrefix(line, "vmess://")
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			b, err = base64.RawStdEncoding.DecodeString(raw)
		}
		if err != nil {
			return 0
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return 0
		}
		return asInt(m["port"])
	}
	u, err := url.Parse(line)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(u.Port())
	return p
}

func findURLByPort(lines []string, port int) int {
	for i, line := range lines {
		if sharePort(line) == port {
			return i
		}
	}
	return -1
}

func setSharePortAndUser(line string, port int, user, pass, frag string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "vmess://") {
		raw := strings.TrimPrefix(line, "vmess://")
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			b, _ = base64.RawStdEncoding.DecodeString(raw)
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			return line
		}
		m["port"] = strconv.Itoa(port)
		if user != "" {
			m["id"] = user
		}
		if frag != "" {
			m["ps"] = frag
		}
		nb, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(nb)
	}
	u, err := url.Parse(line)
	if err != nil {
		return line
	}
	host := u.Hostname()
	if host == "" {
		host = publicHost("")
	}
	u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	if user != "" {
		if pass != "" {
			u.User = url.UserPassword(user, pass)
		} else {
			u.User = url.User(user)
		}
	}
	if frag != "" {
		u.Fragment = frag
	}
	return u.String()
}

func inboundCreds(ib map[string]any) (uuid, password string) {
	if users, ok := ib["users"].([]any); ok && len(users) > 0 {
		if m, ok := users[0].(map[string]any); ok {
			uuid = asString(m["uuid"])
			password = asString(m["password"])
		}
	}
	if password == "" {
		password = asString(ib["password"])
	}
	return
}

func upsertShareURL(sbDir string, oldPort, newPort int, ib map[string]any, cloneFromPort int) {
	lines := loadURLLines(sbDir)
	if lines == nil {
		return
	}
	tag := asString(ib["tag"])
	uuid, password := inboundCreds(ib)
	user, pass := uuid, password
	if uuid == "" {
		user, pass = password, ""
	}
	idx := findURLByPort(lines, oldPort)
	if idx < 0 && cloneFromPort > 0 {
		idx = findURLByPort(lines, cloneFromPort)
		if idx >= 0 {
			lines = append(lines, setSharePortAndUser(lines[idx], newPort, user, pass, tag))
			_ = saveURLLines(sbDir, lines)
			return
		}
	}
	if idx >= 0 {
		lines[idx] = setSharePortAndUser(lines[idx], newPort, user, pass, tag)
		_ = saveURLLines(sbDir, lines)
		return
	}
}

func removeShareURL(sbDir string, port int) {
	lines := loadURLLines(sbDir)
	if lines == nil {
		return
	}
	var keep []string
	for _, line := range lines {
		if sharePort(line) == port && port > 0 {
			continue
		}
		keep = append(keep, line)
	}
	_ = saveURLLines(sbDir, keep)
}

func vmessUUID(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "vmess://") {
		return ""
	}
	raw := strings.TrimPrefix(line, "vmess://")
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(raw)
	}
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	return asString(m["id"])
}

func buildVmessURL(sbDir string, port int, ib map[string]any) string {
	uuid, _ := inboundCreds(ib)
	host := publicHost(sbDir)
	tag := asString(ib["tag"])

	m := map[string]any{
		"v":    "2",
		"ps":   tag,
		"add":  host,
		"port": strconv.Itoa(port),
		"id":   uuid,
		"aid":  "0",
		"scy":  "auto",
		"net":  "tcp",
		"type": "none",
	}
	if tr, ok := ib["transport"].(map[string]any); ok {
		if t := asString(tr["type"]); t != "" {
			m["net"] = t
		}
		if p := asString(tr["path"]); p != "" {
			m["path"] = p
		}
		if h := asString(tr["host"]); h != "" {
			m["host"] = h
		}
	}
	if tls, ok := ib["tls"].(map[string]any); ok {
		if enabled, _ := tls["enabled"].(bool); enabled {
			m["tls"] = "tls"
			if sni := asString(tls["server_name"]); sni != "" {
				m["sni"] = sni
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func shareURLOf(sbDir string, port int, ib map[string]any) string {
	lines := loadURLLines(sbDir)
	for _, line := range lines {
		if sharePort(line) == port && port > 0 {
			return line
		}
	}
	uuid, _ := inboundCreds(ib)
	typ := asString(ib["type"])
	if uuid != "" {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if typ == "vmess" && strings.HasPrefix(line, "vmess://") {
				if vmessUUID(line) == uuid {
					return line
				}
			} else if typ != "" && typ != "vmess" && strings.HasPrefix(line, typ+"://") {
				if u, err := url.Parse(line); err == nil {
					if u.User != nil && u.User.Username() == uuid {
						return line
					}
				}
			}
		}
	}
	if asString(ib["type"]) == "vmess" && uuid != "" && port > 0 {
		return buildVmessURL(sbDir, port, ib)
	}
	return ""
}

func backupSBFiles(dir, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	for _, n := range []string{"inbounds.json", "outbounds.json", "route.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(destDir, n+"."+ts), b, 0o600)
	}
	return nil
}
