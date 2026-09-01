package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netlink6: 通过 rtnetlink 直接 add/del IPv6 地址（无 fork，纯 syscall）。

var (
	linkMu  sync.Mutex
	ifindex = map[string]int{}
)

func linkIdx(name string) (int, error) {
	linkMu.Lock()
	defer linkMu.Unlock()
	if i, ok := ifindex[name]; ok {
		return i, nil
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	ifindex[name] = ifi.Index
	return ifi.Index, nil
}

// nladdrmsg 构造 ifaddrmsg + IFA_LOCAL/IFA_ADDRESS 属性。
func nladdrmsg(addr netip.Addr, prefixlen, ifidx int) []byte {
	a16 := addr.As16()
	data := make([]byte, unix.SizeofIfAddrmsg)
	ia := (*unix.IfAddrmsg)(unsafe.Pointer(&data[0]))
	ia.Family = unix.AF_INET6
	ia.Prefixlen = uint8(prefixlen)
	ia.Index = uint32(ifidx)

	buf := make([]byte, 0, 2*32)
	for _, t := range []uint16{unix.IFA_LOCAL, unix.IFA_ADDRESS} {
		attr := make([]byte, (4+4+len(a16)+3)&^3)
		binary.LittleEndian.PutUint16(attr[0:2], uint16(4+len(a16)))
		binary.LittleEndian.PutUint16(attr[2:4], t)
		copy(attr[4:], a16[:])
		buf = append(buf, attr...)
	}
	return append(data, buf...)
}

func netlinkAddr(ifname string, addr netip.Addr, prefixlen int, typ uint16, flags uint16) error {
	idx, err := linkIdx(ifname)
	if err != nil {
		return err
	}
	body := nladdrmsg(addr, prefixlen, idx)
	msg := unix.NlMsghdr{
		Len:   uint32(nlmsgAlign(nlmsgHdrLen + len(body))),
		Type:  typ,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | flags,
	}
	buf := make([]byte, msg.Len)
	*(*unix.NlMsghdr)(unsafe.Pointer(&buf[0])) = msg
	copy(buf[nlmsgHdrLen:], body)

	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	if err := unix.Bind(sock, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	if err := unix.Sendto(sock, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}); err != nil {
		return err
	}
	ack := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, ack, 0)
	if err != nil {
		return err
	}
	if n >= nlmsgHdrLen {
		hdr := (*unix.NlMsghdr)(unsafe.Pointer(&ack[0]))
		if hdr.Type == unix.NLMSG_ERROR {
			errno := int32(binary.LittleEndian.Uint32(ack[nlmsgHdrLen:]))
			if errno != 0 {
				return unix.Errno(-errno)
			}
		}
	}
	return nil
}

const nlmsgHdrLen = int(unsafe.Sizeof(unix.NlMsghdr{}))

func nlmsgAlign(n int) int { return (n + 3) &^ 3 }

// addAddr6 添加 /128；地址已存在时报 EEXIST（供随机分配重试）。
func addAddr6(ifname string, addr netip.Addr) error {
	return netlinkAddr(ifname, addr, 128, unix.RTM_NEWADDR, unix.NLM_F_CREATE)
}

func delAddr6(ifname string, addr netip.Addr) error {
	return netlinkAddr(ifname, addr, 128, unix.RTM_DELADDR, 0)
}
