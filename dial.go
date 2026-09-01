package main

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// dialTcp 建立到 hostport 的 TCP 连接：
//   - 源地址绑定 bind（IPv6 /64 内地址，需已在接口上）
//   - SO_MARK 写入 mark，命中策略路由走对应 WireGuard 路由表
//   - SO_BINDTODEVICE 强制走 iface
func dialTcp(ctx context.Context, bind netip.Addr, mark int, iface, hostport string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if mark != 0 {
				if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); serr != nil {
					return
				}
			}
			if iface != "" {
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}
		}); err != nil {
			return err
		}
		return serr
	}
	if bind.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: bind.AsSlice(), Port: 0}
	}
	return d.DialContext(ctx, "tcp", hostport)
}
