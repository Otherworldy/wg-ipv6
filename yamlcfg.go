package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

func loadYAMLDoc(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func rootMap(doc *yaml.Node) *yaml.Node {
	if doc != nil && doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0]
	}
	return doc
}

func scalar(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func intNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)}
}

func hexIntNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("0x%x", v)}
}

func yamlMapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func yamlMapSet(m *yaml.Node, key string, val *yaml.Node) {
	if n := yamlMapGet(m, key); n != nil {
		n.Kind, n.Tag, n.Value, n.Content = val.Kind, val.Tag, val.Value, val.Content
		return
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, val)
}

func yamlMapSetString(m *yaml.Node, key, val string) { yamlMapSet(m, key, scalar(val)) }

func writeYAMLDoc(path string, doc *yaml.Node) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return err
	}
	return enc.Close()
}

func yamlAppendTunnel(m *yaml.Node, t TunnelConf) error {
	seq := yamlMapGet(m, "tunnels")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode}
		yamlMapSet(m, "tunnels", seq)
	}
	wg := t.WGConf
	if wg == "" {
		wg = "wg/" + t.Name + ".conf"
	}
	seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "name"}, scalar(t.Name),
		{Kind: yaml.ScalarNode, Value: "wg_conf"}, scalar(wg),
		{Kind: yaml.ScalarNode, Value: "table"}, intNode(t.Table),
		{Kind: yaml.ScalarNode, Value: "mark"}, hexIntNode(t.Mark),
		{Kind: yaml.ScalarNode, Value: "pool_size"}, intNode(t.PoolSize),
		{Kind: yaml.ScalarNode, Value: "pool_start"}, scalar(t.PoolStart),
		{Kind: yaml.ScalarNode, Value: "sticky_start"}, scalar(t.StickyStart),
	}})
	return nil
}

func yamlRemoveTunnel(m *yaml.Node, name string) error {
	seq := yamlMapGet(m, "tunnels")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("no tunnels")
	}
	var kept []*yaml.Node
	found := false
	for _, item := range seq.Content {
		n := yamlMapGet(item, "name")
		if n != nil && n.Value == name {
			found = true
			continue
		}
		kept = append(kept, item)
	}
	if !found {
		return fmt.Errorf("tunnel %s not found", name)
	}
	if len(kept) == 0 {
		return fmt.Errorf("至少保留一条隧道")
	}
	seq.Content = kept
	return nil
}

func nextTableMark(ts []TunnelConf) (int, int) {
	table, mark := 63, 0x3f
	for _, t := range ts {
		if t.Table > table {
			table = t.Table
		}
		if t.Mark > mark {
			mark = t.Mark
		}
	}
	return table + 1, mark + 1
}

func poolDefaults(ts []TunnelConf) (size int, start, sticky string) {
	size, start, sticky = 240, "::10", "::2000"
	if len(ts) == 0 {
		return
	}
	if ts[0].PoolSize > 0 {
		size = ts[0].PoolSize
	}
	if ts[0].PoolStart != "" {
		start = ts[0].PoolStart
	}
	if ts[0].StickyStart != "" {
		sticky = ts[0].StickyStart
	}
	return
}

func sanitizeName(s string) (string, error) {
	s = trimName(s)
	if s == "" || len(s) > 32 {
		return "", fmt.Errorf("名称 1-32 字符")
	}
	for i, r := range s {
		ok := r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok || (i == 0 && (r == '-' || r == '_')) {
			return "", fmt.Errorf("名称仅字母数字和 - _")
		}
	}
	switch s {
	case "all", "help", "default":
		return "", fmt.Errorf("保留名")
	}
	return s, nil
}

func trimName(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func randPassword(n int) string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func ensureAdminPassword(cfg *Config) error {
	if cfg.AdminPassword != "" && cfg.AdminPassword != "CHANGE_ME_ADMIN" {
		return nil
	}
	if cfg.Path == "" {
		return fmt.Errorf("config path empty")
	}
	cfg.AdminPassword = randPassword(20)
	doc, err := loadYAMLDoc(cfg.Path)
	if err != nil {
		return err
	}
	m := rootMap(doc)
	yamlMapSetString(m, "admin_password", cfg.AdminPassword)
	if cfg.AdminListen != "" && yamlMapGet(m, "admin_listen") == nil {
		yamlMapSetString(m, "admin_listen", cfg.AdminListen)
	}
	return writeYAMLDoc(cfg.Path, doc)
}
