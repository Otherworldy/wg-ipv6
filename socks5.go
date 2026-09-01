package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SOCKS5 RFC1928 + RFC1929（用户名密码认证，密码共享、用户名区分账号）。

const (
	socksVersion  = 0x05
	authVersion   = 0x01
	authUserPass  = 0x02
	cmdConnect    = 0x01
	cmdUDP        = 0x03
	repSuccess    = 0x00
	repGeneral    = 0x01
	repRefused    = 0x05
	repNotSupport = 0x07
)

type Server struct {
	cfg     *Config
	store   *Store
	tunnels map[string]*Tunnel
	defTun  *Tunnel
	log     *log.Logger
	sem     chan struct{} // 连接数限流

	ensuredMu sync.Mutex
	ensured   map[string]bool // 已确认在接口上的粘性地址
	eph       *Ephemeral      // 默认账号全随机（nil = 走 numgen 池）
}

func NewServer(cfg *Config, store *Store, tunnels []*Tunnel, logger *log.Logger) *Server {
	m := make(map[string]*Tunnel, len(tunnels))
	var def *Tunnel
	for _, t := range tunnels {
		m[t.Conf.Name] = t
		if t.Conf.Name == cfg.DefaultTunnel {
			def = t
		}
	}
	s := &Server{
		cfg: cfg, store: store, tunnels: m, defTun: def,
		log: logger, sem: make(chan struct{}, cfg.MaxConns),
		ensured: map[string]bool{},
	}
	if cfg.Ephemeral {
		s.eph = NewEphemeral(cfg.EphemeralGrace)
	}
	return s
}

// account 解析后的一次拨号身份
type account struct {
	tun    *Tunnel
	sticky bool
	name   string // 粘性映射键（完整用户名）
}

// parseAccount：
//   - 等于 default_account          -> 默认，随机出口
//   - default_account.<id>          -> 默认隧道粘性
//   - default_account.<tun>.<id>    -> 指定隧道粘性
func (s *Server) parseAccount(username string) (account, error) {
	if username == s.cfg.DefaultAccount {
		return account{tun: s.defTun, sticky: false}, nil
	}
	prefix := s.cfg.DefaultAccount + "."
	if !strings.HasPrefix(username, prefix) {
		return account{}, fmt.Errorf("unknown account (want %s or %s.<id>)", s.cfg.DefaultAccount, s.cfg.DefaultAccount)
	}
	rest := strings.TrimPrefix(username, prefix)
	if rest == "" {
		return account{}, fmt.Errorf("empty account id")
	}
	if a, b, ok := strings.Cut(rest, "."); ok {
		if t, found := s.tunnels[a]; found {
			if b == "" {
				return account{}, fmt.Errorf("empty account id after tunnel")
			}
			return account{tun: t, sticky: true, name: username}, nil
		}
	}
	return account{tun: s.defTun, sticky: true, name: username}, nil
}

// resolve 返回：粘性账号 -> 已绑定地址；默认 -> 隧道基础地址（由 nft 随机 SNAT）。
func (s *Server) resolve(a account) (netip.Addr, error) {
	if !a.sticky {
		if s.eph != nil {
			return s.eph.Acquire(a.tun)
		}
		return a.tun.Base, nil
	}
	addr, err := s.store.Allocate(a.tun, a.name)
	if err != nil {
		return netip.Addr{}, err
	}
	if err := s.ensureAddr(a.tun, addr); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// ForgetAddr 从已确认缓存中移除地址（账号回收后调用，使后续可重新 ensure）。
func (s *Server) ForgetAddr(t *Tunnel, addr netip.Addr) {
	s.ensuredMu.Lock()
	delete(s.ensured, t.Conf.Name+"/"+addr.String())
	s.ensuredMu.Unlock()
}

func (s *Server) ensureAddr(t *Tunnel, addr netip.Addr) error {
	key := t.Conf.Name + "/" + addr.String()
	s.ensuredMu.Lock()
	if s.ensured[key] {
		s.ensuredMu.Unlock()
		return nil
	}
	s.ensuredMu.Unlock()
	if err := t.EnsureAddr(addr); err != nil {
		return err
	}
	s.ensuredMu.Lock()
	s.ensured[key] = true
	s.ensuredMu.Unlock()
	return nil
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.writeReply(c, repGeneral)
		return
	}
	c.SetDeadline(time.Now().Add(15 * time.Second))

	methods, err := readGreeting(c)
	if err != nil {
		return
	}
	if !containsByte(methods, authUserPass) {
		c.Write([]byte{socksVersion, 0xff})
		return
	}
	if _, err := c.Write([]byte{socksVersion, authUserPass}); err != nil {
		return
	}
	user, pass, err := readUserPass(c)
	if err != nil {
		return
	}
	if subtle.ConstantTimeCompare(pass, []byte(s.cfg.Password)) != 1 {
		s.log.Printf("auth failed: user=%q from=%s", string(user), c.RemoteAddr())
		c.Write([]byte{authVersion, 0x01})
		return
	}
	c.Write([]byte{authVersion, 0x00})

	acc, err := s.parseAccount(string(user))
	if err != nil {
		s.log.Printf("reject user=%q: %v", string(user), err)
		s.writeReply(c, repGeneral)
		return
	}
	req, err := readRequest(c)
	if err != nil {
		s.writeReply(c, repGeneral)
		return
	}
	if req.Cmd != cmdConnect {
		s.writeReply(c, repNotSupport)
		return
	}
	s.log.Printf("connect user=%q -> %s (tunnel=%s sticky=%v)", string(user), req.Host, acc.tun.Conf.Name, acc.sticky)
	s.proxy(c, acc, req)
}

func (s *Server) proxy(client net.Conn, acc account, req Request) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ConnectTimeout)
	defer cancel()
	src, err := s.resolve(acc)
	if err != nil {
		s.log.Printf("resolve %s: %v", acc.name, err)
		s.writeReply(client, repGeneral)
		return
	}
	if !acc.sticky && s.eph != nil {
		defer s.eph.Release(acc.tun, src)
	}
	remote, err := dialTcp(ctx, src, acc.tun.Conf.Mark, acc.tun.Conf.Name, req.Host, s.cfg.ConnectTimeout)
	if err != nil {
		s.log.Printf("dial %s: %v", req.Host, err)
		s.writeReply(client, repRefused)
		return
	}
	defer remote.Close()
	if err := s.writeReplyAddr(client, remote.LocalAddr()); err != nil {
		return
	}
	client.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		s.copyBuff(remote, client)
		if t, ok := remote.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		s.copyBuff(client, remote)
		if t, ok := client.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}

func (s *Server) copyBuff(dst, src net.Conn) {
	idle := s.cfg.IdleTimeout
	d := deadlineConn{Conn: dst, idle: idle}
	r := deadlineConn{Conn: src, idle: idle}
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	io.CopyBuffer(&d, &r, *buf)
}

type deadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.idle > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.idle > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Write(b)
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

func (s *Server) writeReply(c net.Conn, rep byte) {
	c.Write([]byte{socksVersion, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func (s *Server) writeReplyAddr(c net.Conn, local net.Addr) error {
	var b []byte
	if ta, ok := local.(*net.TCPAddr); ok {
		port := uint16(ta.Port)
		if ip, ok2 := netip.AddrFromSlice(ta.IP); ok2 {
			ip = ip.Unmap()
			if ip.Is6() {
				b = make([]byte, 22)
				b[3] = 0x04
				ip16 := ip.As16()
				copy(b[4:20], ip16[:])
				binary.BigEndian.PutUint16(b[20:22], port)
			} else {
				b = make([]byte, 10)
				copy(b[4:8], ip.AsSlice())
				binary.BigEndian.PutUint16(b[8:10], port)
			}
		}
	}
	if b == nil {
		b = []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	}
	b[0], b[1], b[2] = socksVersion, repSuccess, 0x00
	_, err := c.Write(b)
	return err
}

// ---- RFC1928/1929 纯解析（单测覆盖） ----

type Request struct {
	Cmd  byte
	Host string
}

func readGreeting(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != socksVersion {
		return nil, fmt.Errorf("bad version %d", hdr[0])
	}
	if hdr[1] == 0 {
		return nil, fmt.Errorf("no methods")
	}
	m := make([]byte, hdr[1])
	if _, err := io.ReadFull(r, m); err != nil {
		return nil, err
	}
	return m, nil
}

func readUserPass(r io.Reader) (user, pass []byte, err error) {
	hdr := make([]byte, 2)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	if hdr[0] != authVersion {
		err = fmt.Errorf("bad auth version %d", hdr[0])
		return
	}
	user = make([]byte, hdr[1])
	if _, err = io.ReadFull(r, user); err != nil {
		return
	}
	plen := make([]byte, 1)
	if _, err = io.ReadFull(r, plen); err != nil {
		return
	}
	if plen[0] == 0 {
		err = fmt.Errorf("empty password")
		return
	}
	pass = make([]byte, plen[0])
	_, err = io.ReadFull(r, pass)
	return
}

func readRequest(r io.Reader) (Request, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Request{}, err
	}
	if hdr[0] != socksVersion || hdr[2] != 0 {
		return Request{}, fmt.Errorf("bad request header")
	}
	req := Request{Cmd: hdr[1]}
	var host []byte
	switch hdr[3] {
	case 0x01:
		host = make([]byte, 4)
		if _, err := io.ReadFull(r, host); err != nil {
			return Request{}, err
		}
		req.Host = net.IP(host).String()
	case 0x04:
		host = make([]byte, 16)
		if _, err := io.ReadFull(r, host); err != nil {
			return Request{}, err
		}
		req.Host = net.IP(host).String()
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return Request{}, err
		}
		if n[0] == 0 {
			return Request{}, fmt.Errorf("empty domain")
		}
		host = make([]byte, n[0])
		if _, err := io.ReadFull(r, host); err != nil {
			return Request{}, err
		}
		req.Host = string(host)
	default:
		return Request{}, fmt.Errorf("bad atyp %d", hdr[3])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		return Request{}, err
	}
	req.Host = net.JoinHostPort(req.Host, strconv.Itoa(int(binary.BigEndian.Uint16(port))))
	return req, nil
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}
