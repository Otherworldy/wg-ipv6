package main

import (
	"bytes"
	"testing"
)

func TestReadGreeting(t *testing.T) {
	m, err := readGreeting(bytes.NewReader([]byte{5, 2, 0, 2}))
	if err != nil || len(m) != 2 || m[0] != 0 || m[1] != 2 {
		t.Fatalf("got %v %v", m, err)
	}
	if _, err := readGreeting(bytes.NewReader([]byte{4, 1, 0})); err == nil {
		t.Fatal("expected bad version error")
	}
}

func TestReadUserPass(t *testing.T) {
	u, p, err := readUserPass(bytes.NewReader([]byte{
		1, 13, '4', '3', 'b', '3', '2', '7', '7', 'e', '.', 'a', 'c', 'c', '1',
		8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	}))
	if err != nil || string(u) != "43b3277e.acc1" || string(p) != "password" {
		t.Fatalf("got %q %q %v", u, p, err)
	}
	if _, _, err := readUserPass(bytes.NewReader([]byte{1, 1, 'x', 0})); err == nil {
		t.Fatal("expected empty password error")
	}
}

func TestReadRequestIPv6(t *testing.T) {
	req, err := readRequest(bytes.NewReader([]byte{
		5, 1, 0, 4,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x01, 0xbb,
	}))
	if err != nil || req.Cmd != cmdConnect || req.Host != "[2001:db8::1]:443" {
		t.Fatalf("got %+v %v", req, err)
	}
}

func TestReadRequestDomain(t *testing.T) {
	req, err := readRequest(bytes.NewReader([]byte{
		5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50,
	}))
	if err != nil || req.Host != "example.com:80" {
		t.Fatalf("got %+v %v", req, err)
	}
}

func TestParseAccount(t *testing.T) {
	cfg := &Config{DefaultAccount: "43b3277e", DefaultTunnel: "route64"}
	s := &Server{cfg: cfg, tunnels: map[string]*Tunnel{
		"route64":   {Conf: TunnelConf{Name: "route64"}},
		"route64-b": {Conf: TunnelConf{Name: "route64-b"}},
	}, defTun: &Tunnel{Conf: TunnelConf{Name: "route64"}}}

	a, err := s.parseAccount("43b3277e")
	if err != nil || a.sticky || a.tun.Conf.Name != "route64" {
		t.Fatalf("default: %+v %v", a, err)
	}
	a, err = s.parseAccount("43b3277e.acc1")
	if err != nil || !a.sticky || a.tun.Conf.Name != "route64" || a.name != "43b3277e.acc1" {
		t.Fatalf("sticky: %+v %v", a, err)
	}
	a, err = s.parseAccount("43b3277e.route64-b.acc7")
	if err != nil || !a.sticky || a.tun.Conf.Name != "route64-b" {
		t.Fatalf("tunnel sticky: %+v %v", a, err)
	}
	if _, err := s.parseAccount("nobody"); err == nil {
		t.Fatal("expected reject")
	}
	if _, err := s.parseAccount("43b3277e."); err == nil {
		t.Fatal("expected reject empty id")
	}
}
