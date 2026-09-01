package main

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func testTunnel(t *testing.T, name, prefix string) *Tunnel {
	t.Helper()
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return &Tunnel{Conf: TunnelConf{Name: name}, Prefix: p, Base: p.Addr(),
		StickyIID: iidOf(netip.MustParseAddr("::2000"))}
}

func TestAllocateStableAndUnique(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	tun := testTunnel(t, "route64", "2a11:6c7:f09:b::2/64")

	a1, err := st.Allocate(tun, "43b3277e.acc3")
	if err != nil || a1.String() != "2a11:6c7:f09:b::2000" {
		t.Fatalf("first alloc: %v %v", a1, err)
	}
	a2, err := st.Allocate(tun, "43b3277e.acc3") // 再次分配 -> 固定
	if err != nil || a2 != a1 {
		t.Fatalf("second alloc not stable: %v %v", a2, err)
	}
	a3, err := st.Allocate(tun, "43b3277e.acc4") // 顺序递增
	if err != nil || a3.String() != "2a11:6c7:f09:b::2001" {
		t.Fatalf("sequence: %v %v", a3, err)
	}
}

func TestSeedSkipsConflict(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	tun := testTunnel(t, "route64", "2a11:6c7:f09:b::2/64")
	if err := st.Seed(tun, "43b3277e.acc1", netip.MustParseAddr("2a11:6c7:f09:b::2000")); err != nil {
		t.Fatal(err)
	}
	a, err := st.Allocate(tun, "43b3277e.acc2")
	if err != nil || a.String() == "2a11:6c7:f09:b::2000" {
		t.Fatalf("alloc clashed with seed: %v %v", a, err)
	}
}

func TestReapIdle(t *testing.T) {
	dir := t.TempDir()
	st, err := LoadStore(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	tun := testTunnel(t, "route64", "2a11:6c7:f09:b::2/64")
	now := time.Now()

	// 新分配账号
	if _, err := st.Allocate(tun, "43b3277e.old1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Allocate(tun, "43b3277e.fresh"); err != nil {
		t.Fatal(err)
	}
	// 把 old1 的 LastUsed 改成 10 天前（模拟闲置）
	old, _ := st.Get("43b3277e.old1")
	old.LastUsed = now.Add(-10 * 24 * time.Hour).Unix()
	rec, _ := st.Get("43b3277e.old1")
	rec.LastUsed = old.LastUsed
	st.records["43b3277e.old1"] = rec

	protected := map[string]bool{"43b3277e.acc1": true}
	removed := st.ReapIdle(now, 720*time.Hour, protected)

	var got []string
	for _, e := range removed {
		got = append(got, e.Rec.Addr)
	}
	// 10 天闲置 < 30 天阈值，不应回收
	if len(got) != 0 {
		t.Fatalf("10-day idle should NOT be reaped at 720h ttl, got %v", got)
	}
	// 用 5 天 TTL 再测：old1 (10 天) 应回收，fresh (现在) 不回收
	removed = st.ReapIdle(now, 120*time.Hour, protected)
	got = nil
	for _, e := range removed {
		got = append(got, e.Rec.Addr)
	}
	if len(got) != 1 || got[0] == "2a11:6c7:f09:b::2001" {
		t.Fatalf("expected only old1 reaped, got %v", got)
	}
	if removed[0].Name != "43b3277e.old1" {
		t.Fatalf("expected old1 reaped, got %s", removed[0].Name)
	}
	if _, ok := st.Get("43b3277e.fresh"); !ok {
		t.Fatal("fresh account should survive")
	}
}
