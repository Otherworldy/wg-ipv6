package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
)

// 批量生成节点：每个用户一条独立 socks5 出站 + auth_user 分流规则，
// 端口/TLS/传输沿用入口模板，所以一个入口可以发 N 份互不干扰的凭据。

type batchNode struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
	Account  string `json:"account"`
	URL      string `json:"url"`
}

// userKind 按入站类型决定凭据形态。
//   - uuid: uuid（vless/vmess）
//   - uuidpass: uuid + password（tuic）
//   - pass: password（trojan/hysteria2/anytls）
//   - userpass: username + password（socks）
func userKind(typ string) (string, bool) {
	switch typ {
	case "vless", "vmess":
		return "uuid", true
	case "tuic":
		return "uuidpass", true
	case "trojan", "hysteria2", "anytls":
		return "pass", true
	case "socks":
		return "userpass", true
	}
	return "", false
}

func shortID(uuid string) string {
	s := strings.ReplaceAll(uuid, "-", "")
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

func (a *admin) batchUsers(w http.ResponseWriter, r *http.Request) {
	inTag := r.PathValue("tag")
	var req struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	kind, tun, nodes, err := generateUsers(a.cfg, inTag, req.Count)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	a.log.Printf("admin batch %s: %s x%d (tunnel=%s)", inTag, kind, len(nodes), tun)
	writeJSON(w, map[string]any{"ok": true, "kind": kind, "tunnel": tun, "nodes": nodes})
}

// generateUsers 给入口追加 count 个用户，每个用户一条独立 socks5 出站 +
// auth_user 分流规则，并把分享链接追加进 url.txt。
func generateUsers(cfg *Config, inTag string, count int) (kind, tun string, nodes []batchNode, err error) {
	if count <= 0 || count > 100 {
		return "", "", nil, fmt.Errorf("数量需要 1-100")
	}
	inb, ob, rt, err := loadSB(cfg.SingBoxDir)
	if err != nil {
		return "", "", nil, err
	}
	_, ib := findInbound(inb.Inbounds, inTag)
	if ib == nil {
		return "", "", nil, fmt.Errorf("入口不存在或已停用")
	}
	typ := asString(ib["type"])
	var ok bool
	if kind, ok = userKind(typ); !ok {
		return "", "", nil, fmt.Errorf("入口类型 %s 暂不支持批量生成（支持 vless/vmess/tuic/trojan/hysteria2/anytls/socks）", typ)
	}
	port := asInt(ib["listen_port"])
	if port <= 0 {
		return "", "", nil, fmt.Errorf("入口没有监听端口")
	}
	if tun = outboundTunnel(cfg, ob, outboundOf(rt, inTag)); tun == "" {
		return "", "", nil, fmt.Errorf("先给该入口指定「粘性 IPv6 出口」，否则生成的节点没有独立地址")
	}
	tmpl := shareURLOf(cfg.SingBoxDir, port, ib)
	if kind != "userpass" && tmpl == "" {
		return "", "", nil, fmt.Errorf("url.txt 里缺少该入口的模板链接，无法生成分享链接（补一行 %s:// 模板后重试）", typ)
	}
	host := ""
	if tmpl != "" {
		if u, uerr := url.Parse(tmpl); uerr == nil {
			host = u.Hostname()
		}
	}
	if host == "" {
		host = publicHost(cfg.SingBoxDir)
	}
	if kind == "userpass" && host == "" {
		return "", "", nil, fmt.Errorf("无法确定对外地址（url.txt 里没有可用主机名），socks 链接生成失败")
	}

	_ = backupSBFiles(cfg.SingBoxDir, filepath.Join(cfg.BaseDir, "backups"))
	err = applySingBox(cfg.SingBoxDir, func(inb *inbFile, ob *obFile, rt map[string]any) error {
		_, ib := findInbound(inb.Inbounds, inTag)
		if ib == nil {
			return fmt.Errorf("入口 %s 已不存在", inTag)
		}
		users, _ := ib["users"].([]any)
		if len(users)+count > 500 {
			return fmt.Errorf("该入口已有 %d 个用户，超过 500 上限", len(users))
		}
		flow := ""
		for _, u := range users {
			if m, ok := u.(map[string]any); ok && flow == "" {
				flow = asString(m["flow"])
			}
		}
		for i := 0; i < count; i++ {
			uuid, pw := newUUID(), randPassword(16)
			id := shortID(uuid)
			name := inTag + "-" + id
			nu := map[string]any{"name": name}
			n := batchNode{Name: name, ID: id, Account: psAccount(cfg, tun, inTag+"-"+id)}
			switch kind {
			case "uuid":
				nu["uuid"] = uuid
				if flow != "" {
					nu["flow"] = flow
				}
				n.UUID = uuid
			case "uuidpass":
				nu["uuid"], nu["password"] = uuid, pw
				n.UUID, n.Password = uuid, pw
			case "pass":
				nu["password"] = pw
				n.Password = pw
			case "userpass":
				delete(nu, "name")
				nu["username"], nu["password"] = name, pw
				n.Username, n.Password = name, pw
			}
			users = append(users, nu)
			ib["users"] = users
			// 顶层凭据与 users[] 互斥，留着会让 sing-box check 失败
			delete(ib, "uuid")
			delete(ib, "password")
			if _, err := attachUserOutbound(cfg, ob, rt, inTag, tun, id, name); err != nil {
				return err
			}
			nodes = append(nodes, n)
		}
		// 链接与 url.txt 一起在锁内写，避免并发批量/改端口时互相覆盖
		added := make([]string, 0, len(nodes))
		for i := range nodes {
			n := &nodes[i]
			switch kind {
			case "uuid":
				n.URL = setSharePortAndUser(tmpl, port, n.UUID, "", n.Name)
			case "uuidpass":
				n.URL = setSharePortAndUser(tmpl, port, n.UUID, n.Password, n.Name)
			case "pass":
				n.URL = setSharePortAndUser(tmpl, port, n.Password, "", n.Name)
			case "userpass":
				n.URL = fmt.Sprintf("socks5://%s:%s@%s:%d#%s",
					url.QueryEscape(n.Username), url.QueryEscape(n.Password), host, port, n.Name)
			}
			added = append(added, n.URL)
		}
		lines := loadURLLines(cfg.SingBoxDir)
		if err := saveURLLines(cfg.SingBoxDir, append(lines, added...)); err != nil {
			return fmt.Errorf("写 url.txt: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	return kind, tun, nodes, nil
}
