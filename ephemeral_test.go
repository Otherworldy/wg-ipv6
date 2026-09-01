package main

import "testing"

func TestRandIIDNoReserved(t *testing.T) {
	seen := map[uint64]bool{}
	for i := 0; i < 2000; i++ {
		iid := randIID()
		if iid == 0 || iid == 1 {
			t.Fatalf("reserved IID generated: %d", iid)
		}
		seen[iid] = true
	}
	// 2000 次碰撞概率 ~ 0 (2^-64 空间)，若大量重复说明 rand 实现有问题
	if len(seen) < 1990 {
		t.Fatalf("too many duplicates: %d unique of 2000", len(seen))
	}
}
