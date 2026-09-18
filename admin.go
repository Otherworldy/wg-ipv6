package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var uiFS embed.FS

const (
	cookieName  = "ps_admin"
	cookieHours = 24
)

var restartProxySticky = func() {
	go func() {
		time.Sleep(300 * time.Millisecond)
		exec.Command("systemctl", "restart", "proxy-sticky").Run()
	}()
}

type admin struct {
	cfg  *Config
	log  *log.Logger
	fail sync.Map // ip -> *failRec
}

type failRec struct {
	n     int
	until time.Time
}

func serveAdmin(cfg *Config, logger *log.Logger) error {
	a := &admin{cfg: cfg, log: logger}
	srv := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           a.wrap(a.routes()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	logger.Printf("admin listening %s", cfg.AdminListen)
	return srv.ListenAndServe()
}

func (a *admin) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.ui)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)
	mux.HandleFunc("GET /api/status", a.auth(a.status))
	mux.HandleFunc("GET /api/tunnels", a.auth(a.listTunnels))
	mux.HandleFunc("POST /api/tunnels", a.auth(a.addTunnel))
	mux.HandleFunc("PUT /api/tunnels/{name}", a.auth(a.putTunnel))
	mux.HandleFunc("DELETE /api/tunnels/{name}", a.auth(a.delTunnel))
	mux.HandleFunc("GET /api/inbounds", a.auth(a.listInbounds))
	mux.HandleFunc("POST /api/inbounds", a.auth(a.addInbound))
	mux.HandleFunc("PUT /api/inbounds/{tag}", a.auth(a.putInbound))
	mux.HandleFunc("DELETE /api/inbounds/{tag}", a.auth(a.delInbound))
	mux.HandleFunc("PUT /api/socks", a.auth(a.putSocks))
	return mux
}

func (a *admin) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func (a *admin) ui(w http.ResponseWriter, r *http.Request) {
	b, err := uiFS.ReadFile("ui.html")
	if err != nil {
		http.Error(w, "ui missing", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func checkPass(got, want string) bool {
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func makeSess(pass string) string {
	exp := time.Now().Add(cookieHours * time.Hour).Unix()
	msg := strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, []byte(pass))
	mac.Write([]byte(msg))
	return msg + "." + hex.EncodeToString(mac.Sum(nil))
}

func validSess(pass, v string) bool {
	msg, sig, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(msg, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	mac := hmac.New(sha256.New, []byte(pass))
	mac.Write([]byte(msg))
	got, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, mac.Sum(nil)) == 1
}

func (a *admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !validSess(a.cfg.AdminPassword, c.Value) {
			writeErr(w, 401, "未登录")
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (a *admin) blocked(ip string) bool {
	v, ok := a.fail.Load(ip)
	if !ok {
		return false
	}
	f := v.(*failRec)
	return time.Now().Before(f.until)
}

func (a *admin) failLogin(ip string) {
	v, _ := a.fail.LoadOrStore(ip, &failRec{})
	f := v.(*failRec)
	f.n++
	if f.n >= 5 {
		f.until = time.Now().Add(10 * time.Minute)
		f.n = 0
	}
}

func (a *admin) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.blocked(ip) {
		writeErr(w, 429, "失败次数过多，10 分钟后再试")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if !checkPass(req.Password, a.cfg.AdminPassword) {
		a.failLogin(ip)
		writeErr(w, 403, "口令错误")
		return
	}
	a.fail.Delete(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    makeSess(a.cfg.AdminPassword),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieHours * 3600,
	})
	writeJSON(w, map[string]any{"ok": true})
}

func (a *admin) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

func (a *admin) status(w http.ResponseWriter, r *http.Request) {
	host := publicHost(a.cfg.SingBoxDir)
	nIn := 0
	if inb, _, _, err := loadSB(a.cfg.SingBoxDir); err == nil {
		nIn = len(inb.Inbounds)
	}
	port := 0
	if _, p, err := net.SplitHostPort(a.cfg.Listen); err == nil {
		port, _ = strconv.Atoi(p)
	}
	writeJSON(w, map[string]any{
		"host": host,
		"socks": map[string]any{
			"listen":          a.cfg.Listen,
			"port":            port,
			"default_account": a.cfg.DefaultAccount,
			"default_tunnel":  a.cfg.DefaultTunnel,
			"password":        a.cfg.Password,
		},
		"admin":    map[string]string{"listen": a.cfg.AdminListen},
		"tunnels":  len(a.cfg.Tunnels),
		"inbounds": nIn,
	})
}

func wgStatus(name string) (up bool, handshake, endpoint, transfer string) {
	if exec.Command("ip", "link", "show", "dev", name).Run() != nil {
		return false, "", "", ""
	}
	out, err := exec.Command("wg", "show", name).Output()
	if err != nil {
		return true, "", "", ""
	}
	up = true
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "endpoint:"):
			endpoint = strings.TrimSpace(strings.TrimPrefix(line, "endpoint:"))
		case strings.HasPrefix(line, "latest handshake:"):
			handshake = strings.TrimSpace(strings.TrimPrefix(line, "latest handshake:"))
		case strings.HasPrefix(line, "transfer:"):
			transfer = strings.TrimSpace(strings.TrimPrefix(line, "transfer:"))
		}
	}
	return
}

func (a *admin) listTunnels(w http.ResponseWriter, r *http.Request) {
	var out []map[string]any
	for _, tc := range a.cfg.Tunnels {
		prefix := ""
		if t, err := parseTunnel(tc); err == nil {
			prefix = t.Prefix.String()
		}
		up, hs, ep, xfer := wgStatus(tc.Name)
		out = append(out, map[string]any{
			"name": tc.Name, "table": tc.Table, "mark": tc.Mark, "prefix": prefix,
			"up": up, "handshake": hs, "endpoint": ep, "transfer": xfer,
			"default": tc.Name == a.cfg.DefaultTunnel,
		})
	}
	writeJSON(w, map[string]any{"tunnels": out})
}

func validateWGConf(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "[Interface]") || !strings.Contains(s, "[Peer]") {
		return netip.Prefix{}, fmt.Errorf("需要 [Interface] 和 [Peer]")
	}
	if !strings.Contains(strings.ToLower(s), "privatekey") {
		return netip.Prefix{}, fmt.Errorf("缺少 PrivateKey")
	}
	return firstV6Address(s)
}

func (a *admin) addTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Conf        string `json:"conf"`
		InboundPort int    `json:"inbound_port"`
		CloneFrom   string `json:"clone_from"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	name, err := sanitizeName(req.Name)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			writeErr(w, 409, "隧道已存在")
			return
		}
	}
	if _, err := validateWGConf(req.Conf); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if exec.Command("ip", "link", "show", "dev", name).Run() == nil {
		writeErr(w, 409, "网卡已存在: "+name)
		return
	}
	table, mark := nextTableMark(a.cfg.Tunnels)
	pool, start, sticky := poolDefaults(a.cfg.Tunnels)
	tc := TunnelConf{Name: name, WGConf: "wg/" + name + ".conf", Table: table, Mark: mark, PoolSize: pool, PoolStart: start, StickyStart: sticky}
	wgPath := filepath.Join(a.cfg.BaseDir, "wg", name+".conf")
	if err := os.MkdirAll(filepath.Dir(wgPath), 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(wgPath, []byte(req.Conf), 0o600); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	doc, err := loadYAMLDoc(a.cfg.Path)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	m := rootMap(doc)
	if err := yamlAppendTunnel(m, tc); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := writeYAMLDoc(a.cfg.Path, doc); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	resp := map[string]any{"ok": true, "name": name, "table": table, "mark": mark, "restarting": true}
	if req.InboundPort > 0 {
		if err := a.cloneVLESSForTunnel(name, mark, req.InboundPort, req.CloneFrom); err != nil {
			resp["inbound_error"] = err.Error()
		} else {
			resp["inbound_port"] = req.InboundPort
		}
	}
	a.log.Printf("admin add tunnel %s table=%d mark=%#x", name, table, mark)
	restartProxySticky()
	writeJSON(w, resp)
}

func (a *admin) cloneVLESSForTunnel(tun string, mark, port int, cloneFrom string) error {
	inb, _, _, err := loadSB(a.cfg.SingBoxDir)
	if err != nil {
		return err
	}
	src := pickClone(inb.Inbounds, cloneFrom)
	if src == nil {
		return fmt.Errorf("没有可克隆的 vless 入口")
	}
	srcPort := asInt(src["listen_port"])
	tag := "vless-" + tun
	return applySingBox(a.cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		if _, exists := findInbound(inb.Inbounds, tag); exists != nil {
			return fmt.Errorf("入口 %s 已存在", tag)
		}
		for _, ib := range inb.Inbounds {
			if asInt(ib["listen_port"]) == port {
				return fmt.Errorf("端口 %d 已被 %s", port, asString(ib["tag"]))
			}
		}
		nb := deepCopyMap(src)
		nb["tag"] = tag
		nb["listen_port"] = port
		refreshCreds(nb)
		inb.Inbounds = append(inb.Inbounds, nb)
		attachTunnelOutbound(ob, rt, tag, tun, mark)
		upsertShareURL(a.cfg.SingBoxDir, port, port, nb, srcPort)
		return nil
	})
}

func pickClone(list []map[string]any, tag string) map[string]any {
	if tag != "" {
		if _, ib := findInbound(list, tag); ib != nil {
			return ib
		}
	}
	var firstVless map[string]any
	for _, ib := range list {
		if asString(ib["type"]) != "vless" {
			continue
		}
		if firstVless == nil {
			firstVless = ib
		}
		if strings.HasPrefix(asString(ib["tag"]), "vless-route64") {
			return ib
		}
	}
	return firstVless
}

func (a *admin) putTunnel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var tc *TunnelConf
	for i := range a.cfg.Tunnels {
		if a.cfg.Tunnels[i].Name == name {
			tc = &a.cfg.Tunnels[i]
			break
		}
	}
	if tc == nil {
		writeErr(w, 404, "没有这条隧道")
		return
	}
	var req struct {
		Conf string `json:"conf"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if _, err := validateWGConf(req.Conf); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := os.WriteFile(tc.WGConf, []byte(req.Conf), 0o600); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	t := &Tunnel{Conf: *tc}
	t.Down()
	a.log.Printf("admin replace tunnel %s", name)
	restartProxySticky()
	writeJSON(w, map[string]any{"ok": true, "restarting": true})
}

func (a *admin) delTunnel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == a.cfg.DefaultTunnel {
		writeErr(w, 400, "先把默认隧道换成别的再删")
		return
	}
	var tc *TunnelConf
	for i := range a.cfg.Tunnels {
		if a.cfg.Tunnels[i].Name == name {
			tc = &a.cfg.Tunnels[i]
			break
		}
	}
	if tc == nil {
		writeErr(w, 404, "没有这条隧道")
		return
	}
	if len(a.cfg.Tunnels) <= 1 {
		writeErr(w, 400, "至少保留一条隧道")
		return
	}
	t := &Tunnel{Conf: *tc}
	t.Down()
	doc, err := loadYAMLDoc(a.cfg.Path)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := yamlRemoveTunnel(rootMap(doc), name); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := writeYAMLDoc(a.cfg.Path, doc); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	bak := filepath.Join(a.cfg.BaseDir, "backups", name+"."+time.Now().Format("20060102-150405")+".conf")
	_ = os.MkdirAll(filepath.Dir(bak), 0o755)
	_ = os.Rename(tc.WGConf, bak)
	disabled := loadDisabled(a.cfg)
	moved := []string{}
	if err := applySingBox(a.cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		moved = stripTunnelFromSB(inb, ob, rt, name, disabled)
		return nil
	}); err != nil {
		a.log.Printf("admin del tunnel %s: sing-box %v", name, err)
	} else {
		_ = saveDisabled(a.cfg, disabled)
	}
	a.log.Printf("admin del tunnel %s", name)
	restartProxySticky()
	writeJSON(w, map[string]any{"ok": true, "restarting": true, "disabled_inbounds": moved})
}

func (a *admin) tunnelMark(name string) (int, bool) {
	for _, t := range a.cfg.Tunnels {
		if t.Name == name {
			return t.Mark, true
		}
	}
	return 0, false
}

func (a *admin) listInbounds(w http.ResponseWriter, r *http.Request) {
	inb, ob, rt, err := loadSB(a.cfg.SingBoxDir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	disabled := loadDisabled(a.cfg)
	var rows []map[string]any
	add := func(ib map[string]any, enabled bool) {
		tag := asString(ib["tag"])
		port := asInt(ib["listen_port"])
		tls, _ := ib["tls"].(map[string]any)
		reality := false
		if tls != nil {
			if rel, _ := tls["reality"].(map[string]any); rel != nil {
				reality = true
			}
		}
		obtag := outboundOf(rt, tag)
		row := map[string]any{
			"tag": tag, "type": asString(ib["type"]), "listen": asString(ib["listen"]),
			"listen_port": port, "enabled": enabled, "outbound": obtag,
			"tunnel": outboundBind(ob, obtag),
			"reality": reality, "url": shareURLOf(a.cfg.SingBoxDir, port),
		}
		rows = append(rows, row)
	}
	for _, ib := range inb.Inbounds {
		add(ib, true)
	}
	for _, ib := range disabled.Inbounds {
		add(ib, false)
	}
	writeJSON(w, map[string]any{"inbounds": rows})
}

func (a *admin) addInbound(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CloneFrom  string `json:"clone_from"`
		Tag        string `json:"tag"`
		ListenPort int    `json:"listen_port"`
		Tunnel     string `json:"tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	tag, err := sanitizeName(req.Tag)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.ListenPort <= 0 || req.ListenPort > 65535 {
		writeErr(w, 400, "端口不合法")
		return
	}
	inb, _, _, err := loadSB(a.cfg.SingBoxDir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	src := pickClone(inb.Inbounds, req.CloneFrom)
	if src == nil {
		writeErr(w, 400, "克隆源不存在")
		return
	}
	srcPort := asInt(src["listen_port"])
	mark := 0
	if req.Tunnel != "" {
		found := false
		for _, t := range a.cfg.Tunnels {
			if t.Name == req.Tunnel {
				mark = t.Mark
				found = true
				break
			}
		}
		if !found {
			writeErr(w, 400, "没有这条隧道")
			return
		}
	}
	_ = backupSBFiles(a.cfg.SingBoxDir, filepath.Join(a.cfg.BaseDir, "backups"))
	err = applySingBox(a.cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		if _, exists := findInbound(inb.Inbounds, tag); exists != nil {
			return fmt.Errorf("入口 %s 已存在", tag)
		}
		for _, ib := range inb.Inbounds {
			if asInt(ib["listen_port"]) == req.ListenPort {
				return fmt.Errorf("端口已被 %s", asString(ib["tag"]))
			}
		}
		nb := deepCopyMap(src)
		nb["tag"] = tag
		nb["listen_port"] = req.ListenPort
		refreshCreds(nb)
		inb.Inbounds = append(inb.Inbounds, nb)
		if req.Tunnel != "" {
			attachTunnelOutbound(ob, rt, tag, req.Tunnel, mark)
		}
		upsertShareURL(a.cfg.SingBoxDir, req.ListenPort, req.ListenPort, nb, srcPort)
		return nil
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "tag": tag, "listen_port": req.ListenPort})
}

func (a *admin) putInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	var req struct {
		ListenPort *int    `json:"listen_port"`
		Listen     *string `json:"listen"`
		Enabled    *bool   `json:"enabled"`
		Tunnel     *string `json:"tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	disabled := loadDisabled(a.cfg)
	_ = backupSBFiles(a.cfg.SingBoxDir, filepath.Join(a.cfg.BaseDir, "backups"))
	err := applySingBox(a.cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		if req.Enabled != nil && !*req.Enabled {
			i, ib := findInbound(inb.Inbounds, tag)
			if ib == nil {
				return fmt.Errorf("入口不存在或已停用")
			}
			disabled.Inbounds = append(disabled.Inbounds, ib)
			inb.Inbounds = append(inb.Inbounds[:i], inb.Inbounds[i+1:]...)
			return nil
		}
		if req.Enabled != nil && *req.Enabled {
			i, ib := findInbound(disabled.Inbounds, tag)
			if ib == nil {
				return fmt.Errorf("停用列表里没有 %s", tag)
			}
			inb.Inbounds = append(inb.Inbounds, ib)
			disabled.Inbounds = append(disabled.Inbounds[:i], disabled.Inbounds[i+1:]...)
			return nil
		}
		i, ib := findInbound(inb.Inbounds, tag)
		if ib == nil {
			return fmt.Errorf("入口不存在")
		}
		oldPort := asInt(ib["listen_port"])
		if req.ListenPort != nil {
			inb.Inbounds[i]["listen_port"] = *req.ListenPort
			upsertShareURL(a.cfg.SingBoxDir, oldPort, *req.ListenPort, inb.Inbounds[i], 0)
		}
		if req.Listen != nil {
			inb.Inbounds[i]["listen"] = *req.Listen
		}
		if req.Tunnel != nil {
			if *req.Tunnel == "" {
				removeRoutesForInbound(rt, tag)
			} else {
				mark, ok := a.tunnelMark(*req.Tunnel)
				if !ok {
					return fmt.Errorf("没有这条隧道")
				}
				attachTunnelOutbound(ob, rt, tag, *req.Tunnel, mark)
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = saveDisabled(a.cfg, disabled)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *admin) delInbound(w http.ResponseWriter, r *http.Request) {
	tag := r.PathValue("tag")
	disabled := loadDisabled(a.cfg)
	_ = backupSBFiles(a.cfg.SingBoxDir, filepath.Join(a.cfg.BaseDir, "backups"))
	var port int
	err := applySingBox(a.cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		i, ib := findInbound(inb.Inbounds, tag)
		if ib != nil {
			port = asInt(ib["listen_port"])
			inb.Inbounds = append(inb.Inbounds[:i], inb.Inbounds[i+1:]...)
			removeRoutesForInbound(rt, tag)
			return nil
		}
		i, ib = findInbound(disabled.Inbounds, tag)
		if ib == nil {
			return fmt.Errorf("入口不存在")
		}
		port = asInt(ib["listen_port"])
		disabled.Inbounds = append(disabled.Inbounds[:i], disabled.Inbounds[i+1:]...)
		return nil
	})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = saveDisabled(a.cfg, disabled)
	removeShareURL(a.cfg.SingBoxDir, port)
	writeJSON(w, map[string]any{"ok": true})
}

func (a *admin) putSocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Listen        string `json:"listen"`
		DefaultTunnel string `json:"default_tunnel"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	doc, err := loadYAMLDoc(a.cfg.Path)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	m := rootMap(doc)
	if req.Listen != "" {
		if _, _, err := net.SplitHostPort(req.Listen); err != nil {
			writeErr(w, 400, "listen 需要 host:port")
			return
		}
		yamlMapSetString(m, "listen", req.Listen)
	}
	if req.DefaultTunnel != "" {
		ok := false
		for _, t := range a.cfg.Tunnels {
			if t.Name == req.DefaultTunnel {
				ok = true
				break
			}
		}
		if !ok {
			writeErr(w, 400, "没有这条隧道")
			return
		}
		yamlMapSetString(m, "default_tunnel", req.DefaultTunnel)
	}
	if err := writeYAMLDoc(a.cfg.Path, doc); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	restartProxySticky()
	writeJSON(w, map[string]any{"ok": true, "restarting": true})
}
