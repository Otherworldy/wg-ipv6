package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type AccountRecord struct {
	Tunnel   string `json:"tunnel"`
	Addr     string `json:"addr"`
	LastUsed int64  `json:"last_used,omitempty"` // unix 秒；0 视为未记录（不回收）
}

// Store 持久化「用户名 -> 粘性出口」映射，首次连接分配，之后固定。
type Store struct {
	mu      sync.Mutex
	path    string
	records map[string]AccountRecord
	next    map[string]uint64 // tunnel -> 下一个可用 IID
}

type storeFile struct {
	Records map[string]AccountRecord `json:"records"`
	Next    map[string]uint64        `json:"next"`
}

func LoadStore(path string) (*Store, error) {
	s := &Store{path: path, records: map[string]AccountRecord{}, next: map[string]uint64{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Records != nil {
		s.records = f.Records
	}
	if f.Next != nil {
		s.next = f.Next
	}
	now := time.Now().Unix()
	for u, r := range s.records {
		if r.LastUsed == 0 {
			r.LastUsed = now
			s.records[u] = r
		}
	}
	return s, nil
}

func (s *Store) Get(username string) (AccountRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[username]
	return r, ok
}

// Seed 幂等写入预置账号（如兼容旧 acc1/acc2）。seed 地址不影响 sticky 分配序列。
// 若 seed 落在 sticky 区间则推进 next 避免重复分配。
func (s *Store) Seed(t *Tunnel, username string, addr netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[username]; ok {
		return nil
	}
	s.records[username] = AccountRecord{Tunnel: t.Conf.Name, Addr: addr.String(), LastUsed: time.Now().Unix()}
	if iid := iidOf(addr); iid >= t.StickyIID && iid >= s.next[t.Conf.Name] {
		s.next[t.Conf.Name] = iid + 1
	}
	return s.saveLocked()
}

// Allocate 为粘性账号分配出口地址：已存在直接返回；否则从 sticky start 起递增。
func (s *Store) Allocate(t *Tunnel, username string) (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.records[username]; ok {
		a, err := netip.ParseAddr(r.Addr)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("record %s corrupt: %w", username, err)
		}
		r.LastUsed = time.Now().Unix()
		s.records[username] = r
		if err := s.saveLocked(); err != nil {
			return netip.Addr{}, err
		}
		return a, nil
	}
	used := make(map[string]bool, len(s.records))
	for _, r := range s.records {
		used[r.Addr] = true
	}
	next := s.next[t.Conf.Name]
	if next == 0 || next < t.StickyIID {
		next = t.StickyIID
	}
	for {
		addr := t.IIDAddr(next)
		next++
		if used[addr.String()] {
			continue
		}
		s.records[username] = AccountRecord{Tunnel: t.Conf.Name, Addr: addr.String(), LastUsed: time.Now().Unix()}
		s.next[t.Conf.Name] = next
		if err := s.saveLocked(); err != nil {
			return netip.Addr{}, err
		}
		return addr, nil
	}
}

// ReapEntry 被回收的账号（带用户名，供日志）。
type ReapEntry struct {
	Name string
	Rec  AccountRecord
}

// ReapIdle 删除超过 ttl 未使用的账号（protected 中的账号跳过）。
// 返回被删除的条目，调用方负责清理接口地址。
func (s *Store) ReapIdle(now time.Time, ttl time.Duration, protected map[string]bool) []ReapEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-ttl).Unix()
	var removed []ReapEntry
	for u, r := range s.records {
		if protected[u] {
			continue
		}
		if r.LastUsed > 0 && r.LastUsed < cutoff {
			delete(s.records, u)
			removed = append(removed, ReapEntry{Name: u, Rec: r})
		}
	}
	if len(removed) > 0 {
		if err := s.saveLocked(); err != nil {
			// 保存失败不回滚内存：下次扫描会重试；仅记录调用方日志
		}
	}
	return removed
}

// Unregister 删除账号映射。
func (s *Store) Unregister(username string) (AccountRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[username]
	if ok {
		delete(s.records, username)
		s.saveLocked()
	}
	return r, ok
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(storeFile{Records: s.records, Next: s.next}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
