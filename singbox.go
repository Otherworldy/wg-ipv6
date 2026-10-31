package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type inbFile struct {
	Inbounds []map[string]any `json:"inbounds"`
}

type obFile struct {
	Outbounds []map[string]any `json:"outbounds"`
}

var (
	singboxBin     = "/etc/sing-box/sing-box"
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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

var sbMu sync.Mutex // applySingBox 串行化：避免并发改写三份 json 互相覆盖

func applySingBox(dir string, mut func(inb *inbFile, ob *obFile, rt map[string]any) error) error {
	sbMu.Lock()
	defer sbMu.Unlock()
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

// psSocksAddr 返回本机 proxy-sticky SOCKS5 的 loopback 地址（sing-box 出站回链目标）。
func psSocksAddr(cfg *Config) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return "", 0, fmt.Errorf("listen %q: %w", cfg.Listen, err)
	}
	if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("listen %q: 端口不合法", cfg.Listen)
	}
	switch strings.Trim(h, "[]") {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	default:
		host = strings.Trim(h, "[]")
	}
	return host, port, nil
}

// psAccount 入口 inTag 在 proxy-sticky 上的固定账号：<default_account>.<tunnel>.<tag>。
// 该用户名被 parseAccount 解析为「指定隧道的粘性账号」，即一个入口固定一个 /128 出口。
func psAccount(cfg *Config, tun, inTag string) string {
	return cfg.DefaultAccount + "." + tun + "." + inTag
}

func psOutboundTag(inTag string) string { return "ps-" + inTag }

// tunnelOfAccount 从 <default_account>.<tunnel>.<tag> 反解隧道名。
func tunnelOfAccount(cfg *Config, user string) string {
	rest, ok := strings.CutPrefix(user, cfg.DefaultAccount+".")
	if !ok {
		return ""
	}
	tun, _, ok := strings.Cut(rest, ".")
	if !ok {
		return ""
	}
	for _, t := range cfg.Tunnels {
		if t.Name == tun {
			return tun
		}
	}
	return ""
}

// outboundTunnel 返回出站关联的隧道名：ps-* 出站从账号反解，旧出站看 bind_interface。
func outboundTunnel(cfg *Config, ob *obFile, obTag string) string {
	if ob == nil || obTag == "" || obTag == "direct" {
		return ""
	}
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) != obTag {
			continue
		}
		if asString(o["type"]) == "socks" {
			return tunnelOfAccount(cfg, asString(o["username"]))
		}
		return asString(o["bind_interface"])
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

func prependRouteAuthUser(rt map[string]any, inTag, authUser, outbound string) {
	rule := map[string]any{"inbound": []any{inTag}, "auth_user": []any{authUser}, "outbound": outbound}
	setRouteRules(rt, append([]any{rule}, routeRules(rt)...))
}

// removePlainRoutesForInbound 只删除该入口「不带 auth_user」的规则，保留按用户分流的规则。
func removePlainRoutesForInbound(rt map[string]any, tag string) {
	var keep []any
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m != nil && matchInboundTag(m["inbound"], tag) && len(authUsersOf(m)) == 0 {
			continue
		}
		keep = append(keep, r)
	}
	setRouteRules(rt, keep)
}

func authUsersOf(m map[string]any) []any {
	l, _ := m["auth_user"].([]any)
	return l
}

// insertPlainRoute 把入口的通用规则插到该入口所有 auth_user 规则之后：
// sing-box 顺序匹配，通用规则若排在前面，按用户分流的规则就永远命中不了。
func insertPlainRoute(rt map[string]any, inTag, outbound string) {
	rules := routeRules(rt)
	pos := 0
	for i, r := range rules {
		m, _ := r.(map[string]any)
		if m != nil && matchInboundTag(m["inbound"], inTag) && len(authUsersOf(m)) > 0 {
			pos = i + 1
		}
	}
	rule := map[string]any{"inbound": []any{inTag}, "outbound": outbound}
	rules = append(rules[:pos], append([]any{rule}, rules[pos:]...)...)
	setRouteRules(rt, rules)
}

// removeRoutesForAuthUser 删除该入口按用户分流的旧规则（按 auth_user 精确匹配，不动其它规则）。
func removeRoutesForAuthUser(rt map[string]any, inTag, authUser string) {
	var keep []any
	for _, r := range routeRules(rt) {
		m, _ := r.(map[string]any)
		if m != nil && matchInboundTag(m["inbound"], inTag) && matchInboundTag(m["auth_user"], authUser) {
			continue
		}
		keep = append(keep, r)
	}
	setRouteRules(rt, keep)
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

// attachTunnelOutbound 让入口 inTag 经本机 proxy-sticky 的 SOCKS5 出站：
// 账号固定为 <default_account>.<tunnel>.<tag>，由 proxy-sticky 分配粘性 IPv6 出口，
// 因此每个入口一个账号、一个固定源地址（不再是 direct + bind_interface + numgen 池）。
// psOutboundConfig 构造回链本程序 SOCKS5 的出站配置。
func psOutboundConfig(cfg *Config, obTag, acct string) (map[string]any, error) {
	host, port, err := psSocksAddr(cfg)
	if err != nil {
		return nil, err
	}
	if len(acct) > 200 {
		return nil, fmt.Errorf("账号名过长: %s", acct)
	}
	return map[string]any{
		"type":        "socks",
		"tag":         obTag,
		"server":      host,
		"server_port": port,
		"version":     "5",
		"username":    acct,
		"password":    cfg.Password,
		"network":     "tcp", // proxy-sticky 只做 TCP CONNECT，UDP 不走这里
	}, nil
}

func upsertOutbound(ob *obFile, nb map[string]any) {
	tag := asString(nb["tag"])
	for i, o := range ob.Outbounds {
		if asString(o["tag"]) == tag {
			ob.Outbounds[i] = nb
			return
		}
	}
	ob.Outbounds = append(ob.Outbounds, nb)
}

func attachTunnelOutbound(cfg *Config, ob *obFile, rt map[string]any, inTag, tun string) error {
	obTag := psOutboundTag(inTag)
	nb, err := psOutboundConfig(cfg, obTag, psAccount(cfg, tun, inTag))
	if err != nil {
		return err
	}
	upsertOutbound(ob, nb)
	// 每用户出站跟着换隧道/端口，保留各自 id，auth_user 规则不动
	for i, o := range ob.Outbounds {
		id, ok := psUserID(inTag, asString(o["tag"]))
		if !ok {
			continue
		}
		unb, err := psOutboundConfig(cfg, asString(o["tag"]), psAccount(cfg, tun, inTag+"-"+id))
		if err != nil {
			return err
		}
		ob.Outbounds[i] = unb
	}
	// 只重写「不带 auth_user」的通用规则，按用户分流的规则要留着
	removePlainRoutesForInbound(rt, inTag)
	insertPlainRoute(rt, inTag, obTag)
	pruneTunnelOutbounds(ob, rt)
	return nil
}

// attachUserOutbound 给入口里的单个用户分配独立出站：账号 <acc>.<隧道>.<入口>-<id>，
// 并用 auth_user 规则把该用户（users[].name / socks 的 username）分流到它。
func attachUserOutbound(cfg *Config, ob *obFile, rt map[string]any, inTag, tun, id, authUser string) (string, error) {
	obTag := psUserOutboundTag(inTag, id)
	nb, err := psOutboundConfig(cfg, obTag, psAccount(cfg, tun, inTag+"-"+id))
	if err != nil {
		return "", err
	}
	upsertOutbound(ob, nb)
	removeRoutesForAuthUser(rt, inTag, authUser)
	prependRouteAuthUser(rt, inTag, authUser, obTag)
	return obTag, nil
}

func psUserOutboundTag(inTag, id string) string { return "psu-" + inTag + "-" + id }

// psUserID 反向解析 psu-<inTag>-<8位hex>。后缀必须是 8 位小写 hex，
// 否则 "vless-a" 会误吃邻居入口 "vless-a-b" 的出站。
func psUserID(inTag, obTag string) (string, bool) {
	rest, ok := strings.CutPrefix(obTag, "psu-"+inTag+"-")
	if !ok || len(rest) != 8 {
		return "", false
	}
	for _, c := range rest {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return rest, true
}

// pruneTunnelOutbounds 删除已无引用的旧「direct + bind_interface」隧道出站。
// 只清理本程序旧版本生成的 wg-<接口名> 形式，手写的出站不碰；嵌套引用
// （logical 子规则、selector/urltest、dns.detour）无法完全枚举，故宁少勿多。
func pruneTunnelOutbounds(ob *obFile, rt map[string]any) {
	used := map[string]bool{}
	if r, ok := rt["route"].(map[string]any); ok {
		used[asString(r["final"])] = true
		if sets, ok := r["rule_set"].([]any); ok {
			for _, s := range sets {
				if m, ok := s.(map[string]any); ok {
					used[asString(m["download_detour"])] = true
				}
			}
		}
	}
	for _, r := range routeRules(rt) {
		if m, ok := r.(map[string]any); ok {
			used[asString(m["outbound"])] = true
		}
	}
	var keep []map[string]any
	for _, o := range ob.Outbounds {
		tag := asString(o["tag"])
		legacy := asString(o["type"]) == "direct" && tag == "wg-"+asString(o["bind_interface"])
		if legacy && !used[tag] {
			continue
		}
		keep = append(keep, o)
	}
	ob.Outbounds = keep
}

// dropPSOutbound 入站不再绑定隧道/被删除时，删掉它名下的 socks 出站（含每用户出站）。
func dropPSOutbound(ob *obFile, inTag string) {
	var keep []map[string]any
	for _, o := range ob.Outbounds {
		if tag := asString(o["tag"]); tag == psOutboundTag(inTag) {
			continue
		} else if _, ok := psUserID(inTag, tag); ok {
			continue
		}
		keep = append(keep, o)
	}
	ob.Outbounds = keep
}

func stripTunnelFromSB(cfg *Config, inb *inbFile, ob *obFile, rt map[string]any, tun string, disabled *inbFile) []string {
	dropOB := map[string]bool{}
	var keepOB []map[string]any
	for _, o := range ob.Outbounds {
		if outboundTunnel(cfg, ob, asString(o["tag"])) == tun {
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

// migrateInbounds 把绑定了隧道、但还在用旧 direct+bind_interface 出站的入口，
// 改成经本机 proxy-sticky 的 SOCKS5 出站（每个入口一个固有粘性账号）。
// syncEntryOutbounds 让 sing-box 的入口出站与本程序的 listen 地址保持一致：
//   - 旧版 direct+bind_interface（绑了已知隧道）-> 改成 socks5 回链
//   - 已是 ps-* 但 server/port 与当前 listen 不符（改了监听端口）-> 重写
//
// 幂等；没有要改的就不写盘、不重启 sing-box。
func syncEntryOutbounds(cfg *Config, logger *log.Logger) error {
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		return err
	}
	host, port, err := psSocksAddr(cfg)
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		known[t.Name] = true
	}
	type job struct{ tag, tun string }
	var jobs []job
	scan := func(list []map[string]any) {
		for _, ib := range list {
			tag := asString(ib["tag"])
			tun := entryTunnel(cfg, ob, rt, tag)
			if !known[tun] {
				continue
			}
			if !entryOutboundsStale(cfg, ob, tag, host, port) {
				continue
			}
			jobs = append(jobs, job{tag, tun})
		}
	}
	scan(inb.Inbounds)
	scan(loadDisabled(cfg).Inbounds)
	if len(jobs) == 0 {
		logger.Printf("sync-singbox: 没有需要更新的入口")
		return nil
	}
	if err := backupSBFiles(cfg.SingBoxDir, filepath.Join(cfg.BaseDir, "backups")); err != nil {
		return fmt.Errorf("备份 sing-box 配置失败: %w", err)
	}
	err = applySingBox(cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		for _, j := range jobs {
			if err := attachTunnelOutbound(cfg, ob, rt, j.tag, j.tun); err != nil {
				return fmt.Errorf("%s: %w", j.tag, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, j := range jobs {
		logger.Printf("sync-singbox: %s -> socks5 %s:%d (账号 %s)", j.tag, host, port, psAccount(cfg, j.tun, j.tag))
	}
	return nil
}

// psOutboundMatches 出站是否已指向当前 listen。
func psOutboundMatches(ob *obFile, obTag, host string, port int) bool {
	for _, o := range ob.Outbounds {
		if asString(o["tag"]) != obTag {
			continue
		}
		return asString(o["server"]) == host && asInt(o["server_port"]) == port &&
			asString(o["network"]) == "tcp" &&
			asString(o["username"]) != "" && asString(o["password"]) != ""
	}
	return false
}

// entryTunnel 取入口当前绑定的隧道：共享出站 -> 每用户出站 -> 旧规则。
func entryTunnel(cfg *Config, ob *obFile, rt map[string]any, inTag string) string {
	if tun := outboundTunnel(cfg, ob, psOutboundTag(inTag)); tun != "" {
		return tun
	}
	for _, o := range ob.Outbounds {
		if _, ok := psUserID(inTag, asString(o["tag"])); ok {
			if tun := tunnelOfAccount(cfg, asString(o["username"])); tun != "" {
				return tun
			}
		}
	}
	return outboundTunnel(cfg, ob, outboundOf(rt, inTag))
}

// entryOutboundsStale 判断入口的出站是否还指向当前 listen（共享出站与每用户出站都要看）。
func entryOutboundsStale(cfg *Config, ob *obFile, inTag, host string, port int) bool {
	if !psOutboundMatches(ob, psOutboundTag(inTag), host, port) {
		return true
	}
	for _, o := range ob.Outbounds {
		if _, ok := psUserID(inTag, asString(o["tag"])); !ok {
			continue
		}
		if !psOutboundMatches(ob, asString(o["tag"]), host, port) {
			return true
		}
		if tunnelOfAccount(cfg, asString(o["username"])) == "" {
			return true
		}
	}
	return false
}

// entryAccounts 返回 sing-box 入口占用的账号（<acc>.<tunnel>.<tag>[/ -id]），
// 用于跳过闲置回收：入口账号必须永久固定，地址不能变。
func entryAccounts(cfg *Config) map[string]bool {
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	scan := func(list []map[string]any) {
		for _, ib := range list {
			tag := asString(ib["tag"])
			if outboundOf(rt, tag) == "direct" {
				continue
			}
			shared := psOutboundTag(tag)
			for _, o := range ob.Outbounds {
				ot := asString(o["tag"])
				if _, ok := psUserID(tag, ot); ot != shared && !ok {
					continue
				}
				if u := asString(o["username"]); tunnelOfAccount(cfg, u) != "" {
					out[u] = true
				}
			}
		}
	}
	scan(inb.Inbounds)
	scan(loadDisabled(cfg).Inbounds)
	return out
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
	return os.WriteFile(urlTxtPath(sbDir), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
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
	if oldPort == newPort {
		return
	}
	tag := asString(ib["tag"])
	uuid, password := inboundCreds(ib)
	user, pass := uuid, password
	if uuid == "" {
		user, pass = password, ""
	}
	hit := 0
	for i, line := range lines {
		if sharePort(line) != oldPort || oldPort == 0 {
			continue
		}
		// 保留各自凭据与备注，只换端口；入口自身那一行顺带刷新凭据
		if hit == 0 && tag != "" {
			lines[i] = setSharePortAndUser(line, newPort, user, pass, tag)
		} else {
			lines[i] = setSharePortAndUser(line, newPort, "", "", "")
		}
		hit++
	}
	if hit > 0 {
		_ = saveURLLines(sbDir, lines)
		return
	}
	if cloneFromPort > 0 {
		if idx := findURLByPort(lines, cloneFromPort); idx >= 0 {
			lines = append(lines, setSharePortAndUser(lines[idx], newPort, user, pass, tag))
			_ = saveURLLines(sbDir, lines)
		}
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

// linkMatchesInbound 判断 url.txt 里的模板行是否真的描述这个入口：
// 传输层（ws/grpc/http）和 TLS 形态（reality/tls/none）对不上时，模板就是错的
// （比如 ws 入口借用了别的入口的 reality 链接），照着它发出去的节点一律连不上。
func linkMatchesInbound(line string, ib map[string]any) bool {
	u, err := url.Parse(strings.TrimSpace(line))
	if err != nil || u.Hostname() == "" {
		return false
	}
	q := u.Query()
	wantNet := "tcp"
	if tr, ok := ib["transport"].(map[string]any); ok {
		if t := asString(tr["type"]); t != "" {
			wantNet = t
		}
	}
	gotNet := q.Get("type")
	if gotNet == "" {
		gotNet = "tcp"
	}
	if gotNet != wantNet {
		return false
	}
	wantSec := "none"
	if tls, ok := ib["tls"].(map[string]any); ok {
		if en, _ := tls["enabled"].(bool); en {
			wantSec = "tls"
			if r, ok := tls["reality"].(map[string]any); ok {
				if en, _ := r["enabled"].(bool); en {
					wantSec = "reality"
				}
			}
		}
	}
	gotSec := q.Get("security")
	if gotSec == "" {
		gotSec = "none"
	}
	return gotSec == wantSec
}

// buildVlessURL 用入口自身配置拼 vless 链接（模板缺失或与入口不一致时兜底）。
func buildVlessURL(sbDir string, port int, ib map[string]any, uuid, name string) string {
	host := publicHost(sbDir)
	if host == "" || uuid == "" || port <= 0 {
		return ""
	}
	flow := ""
	if users, ok := ib["users"].([]any); ok {
		for _, u := range users {
			if m, ok := u.(map[string]any); ok {
				if f := asString(m["flow"]); f != "" {
					flow = f
					break
				}
			}
		}
	}
	q := url.Values{}
	q.Set("encryption", "none")
	if flow != "" {
		q.Set("flow", flow)
	}
	if tr, ok := ib["transport"].(map[string]any); ok {
		if t := asString(tr["type"]); t != "" && t != "tcp" {
			q.Set("type", t)
		}
		if p := asString(tr["path"]); p != "" {
			q.Set("path", p)
		}
		if h := asString(tr["host"]); h != "" {
			q.Set("host", h)
		}
		if sn := asString(tr["service_name"]); sn != "" {
			q.Set("serviceName", sn)
		}
	}
	sec := "none"
	if tls, ok := ib["tls"].(map[string]any); ok {
		if en, _ := tls["enabled"].(bool); en {
			sec = "tls"
			if r, ok := tls["reality"].(map[string]any); ok {
				if en, _ := r["enabled"].(bool); en {
					sec = "reality"
					q.Set("pbk", asString(r["public_key"]))
					if sid := asString(r["short_id"]); sid != "" {
						q.Set("sid", sid)
					}
				}
			}
			if sni := asString(tls["server_name"]); sni != "" {
				q.Set("sni", sni)
			}
			if ut, ok := tls["utls"].(map[string]any); ok {
				if fp := asString(ut["fingerprint"]); fp != "" {
					q.Set("fp", fp)
				}
			}
		}
	}
	q.Set("security", sec)
	if name == "" {
		name = asString(ib["tag"])
	}
	return "vless://" + uuid + "@" + host + ":" + strconv.Itoa(port) + "?" + q.Encode() + "#" + name
}

func shareURLOf(sbDir string, port int, ib map[string]any) string {
	// 只有 vless/vmess 能凭入口配置自己拼出链接，其它类型没有更好的来源，模板照用
	synth := asString(ib["type"]) == "vless" || asString(ib["type"]) == "vmess"
	lines := loadURLLines(sbDir)
	for _, line := range lines {
		if sharePort(line) == port && port > 0 {
			if !synth || linkMatchesInbound(line, ib) {
				return line
			}
			break // 端口命中了但传输/TLS 对不上，会误导，改用入口自身配置拼
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
					if u.User != nil && u.User.Username() == uuid && (!synth || linkMatchesInbound(line, ib)) {
						return line
					}
				}
			}
		}
	}
	switch asString(ib["type"]) {
	case "vmess":
		if uuid != "" && port > 0 {
			return buildVmessURL(sbDir, port, ib)
		}
	case "vless":
		return buildVlessURL(sbDir, port, ib, uuid, "")
	}
	return ""
}

func backupSBFiles(dir, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	if b, err := os.ReadFile(urlTxtPath(dir)); err == nil {
		_ = os.WriteFile(filepath.Join(destDir, "url.txt."+ts), b, 0o600)
	}
	for _, n := range []string{"inbounds.json", "outbounds.json", "route.json"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(destDir, n+"."+ts), b, 0o600)
	}
	return nil
}
