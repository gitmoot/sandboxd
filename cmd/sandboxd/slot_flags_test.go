package main

import (
	"context"
	"strings"
	"testing"
)

func TestServiceRequiresSlotsAndBoundsCapacityByThem(t *testing.T) {
	base := []string{"-db", "/nonexistent/ledger.sqlite", "-api-key-file", "/nonexistent/key", "-image", "linux-arm64",
		"-pin-image", "example/pin@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "-pf-socket", "/nonexistent/pf.sock",
		"-template", "review-arm64", "-domain", "sandbox.example", "-gateway-host", "gw.example", "-worker-id", "mac-local"}
	const slot1 = "name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64"
	const slot2 = "name=sandboxd-slot-2,ipv4=192.168.131.0/24,gw=192.168.131.1,ipv6=fd1e:68b8:2ef4:5d02::/64"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "network slots are required"},
		{[]string{"-slot", slot1, "-slot", slot2, "-max-vms", "3"}, "max-vms must be between 1 and the 2 configured slots"},
		{[]string{"-slot", slot1, "-slot", slot1}, "configured twice"},
		{[]string{"-slot", "name=sandboxd-slot-1"}, "all required"},
		// Valid slots with derived capacity get as far as reading the API key.
		{[]string{"-slot", slot1, "-slot", slot2}, "read API key"},
	} {
		err := run(context.Background(), append(append([]string(nil), base...), tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %q: got %v, want %q", tc.args, err, tc.want)
		}
	}
}
