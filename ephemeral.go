package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"net/netip"
	"sync"
	"time"
)

// Ephemeral 默认账号出口：每个新连接从全 /64 随机 IID 生成临时 /128，
// 连接关闭后延迟删除（等 conntrack 回程结束）。随机区间避开已分配地址。
type Ephemeral struct {
	mu    sync.Mutex
	used  map[string]map[uint64]bool // ifname -> 已分配 IID（未释放）
	grace time.Duration
}

func NewEphemeral(grace time.Duration) *Ephemeral {
	return &Ephemeral{used: map[string]map[uint64]bool{}, grace: grace}
}

// Acquire 随机 IID -> add /128 -> 返回可绑定地址。
// 冲突（EEXIST）时重试；netlink 失败回退基础地址（走 nft 池 SNAT，保持可用）。
func (e *Ephemeral) Acquire(t *Tunnel) (netip.Addr, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	byIf := e.used[t.Conf.Name]
	if byIf == nil {
		byIf = map[uint64]bool{}
		e.used[t.Conf.Name] = byIf
	}
	for i := 0; i < 16; i++ {
		iid := randIID()
		if iid == 0 || iid == 1 { // 保留 IID
			continue
		}
		if byIf[iid] {
			continue
		}
		addr := t.IIDAddr(iid)
		if err := addAddr6(t.Conf.Name, addr); err != nil {
			if i < 15 {
				continue // EEXIST 或其他瞬时错误 -> 换一个 IID
			}
			log.Printf("ephemeral: add %s failed: %v (fallback to base/pool)", addr, err)
			return t.Base, nil
		}
		byIf[iid] = true
		return addr, nil
	}
	log.Printf("ephemeral: no free IID after retries (fallback to base/pool)")
	return t.Base, nil
}

// Release 延迟删除临时地址。
func (e *Ephemeral) Release(t *Tunnel, addr netip.Addr) {
	if addr == t.Base {
		return
	}
	time.AfterFunc(e.grace, func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		if err := delAddr6(t.Conf.Name, addr); err != nil {
			log.Printf("ephemeral: del %s failed: %v", addr, err)
		}
		if byIf := e.used[t.Conf.Name]; byIf != nil {
			delete(byIf, iidOf(addr))
		}
	})
}

func randIID() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}
