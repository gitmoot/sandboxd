package main

import (
	"context"
	"strings"
	"testing"
)

func TestDriverSelectionAndFirecrackerCap(t *testing.T) {
	common := []string{"-db", "/nonexistent/ledger.sqlite", "-api-key-file", "/nonexistent/key",
		"-template", "review-amd64", "-domain", "sandbox.example", "-gateway-host", "gw.example", "-worker-id", "linux-local"}
	const slot = "name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-driver", "qemu", "-image", "/x.ext4"}, `unknown driver "qemu"`},
		// The Apple driver still needs its PF helper and bridge pin.
		{[]string{"-image", "linux-arm64", "-slot", slot}, "plus pin-image and pf-socket for the apple driver"},
		// Firecracker refuses Apple-only isolation flags instead of ignoring them.
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-slot", slot}, "apply only to the apple driver"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-pf-socket", "/run/pf.sock"}, "apply only to the apple driver"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-model-relay-target", "127.0.0.1:1"}, "apply only to the apple driver"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-max-vms", "65"}, "max-vms must be between 1 and 64"},
		// Without -max-vms the cap defaults to 2, and a valid configuration
		// gets as far as reading the API key.
		{[]string{"-driver", "firecracker", "-image", "/x.ext4"}, "read API key"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-max-vms", "4"}, "read API key"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-fc-deny-cidr", "203.0.113.7/24"}, "is not a network prefix"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-fc-deny-cidr", "metadata"}, "invalid value"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-fc-deny-cidr", "203.0.113.0/24", "-fc-deny-cidr", "2001:db8::/32"}, "read API key"},
	} {
		err := run(context.Background(), append(append([]string(nil), common...), tc.args...))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %q: got %v, want %q", tc.args, err, tc.want)
		}
	}
}
