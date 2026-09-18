package main

import (
	"strings"
	"testing"
)

func TestIp6RuleAddArgs(t *testing.T) {
	got := ip6RuleAddArgs(10064, 0x40, 64)
	want := []string{"-6", "rule", "add", "pref", "10064", "from", "all", "fwmark", "0x40/0xff", "lookup", "64"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, a := range got {
		if strings.Contains(a, " ") {
			t.Fatalf("combined argv %q", a)
		}
	}
}
