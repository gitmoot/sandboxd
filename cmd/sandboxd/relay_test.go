package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestModelRelayForwardsOnlyPermittedGuestSources(t *testing.T) {
	var requests atomic.Int32
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "fixed broker response")
	}))
	defer broker.Close()
	target := strings.TrimPrefix(broker.URL, "http://")
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}

	for _, tc := range []struct {
		name    string
		guest   string
		allowed bool
	}{
		{name: "guest", guest: "127.0.0.0/8", allowed: true},
		{name: "foreign source", guest: "192.168.128.0/24", allowed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- serveModelRelay(ctx, listener, target, netip.MustParsePrefix(tc.guest)) }()
			before := requests.Load()
			resp, err := client.Get("http://" + listener.Addr().String() + "/model")
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr != nil || string(body) != "fixed broker response" || requests.Load() != before+1 {
					t.Fatalf("guest did not reach fixed broker: %q, %v", body, readErr)
				}
			} else if err == nil || requests.Load() != before {
				if resp != nil {
					_ = resp.Body.Close()
				}
				t.Fatalf("foreign source reached broker: %v", err)
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("relay did not shut down: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("relay did not shut down")
			}
		})
	}
}

func TestModelRelayRefusesBroadGuestCIDRAndNonLoopbackTarget(t *testing.T) {
	for _, guest := range []string{"0.0.0.0/0", "8.8.8.0/24", "192.168.128.17/24"} {
		listener, _, err := openModelRelay("127.0.0.1:0", "127.0.0.1:43184", guest)
		if listener != nil {
			_ = listener.Close()
		}
		if err == nil {
			t.Fatalf("unsafe guest CIDR %q accepted", guest)
		}
	}
	for _, target := range []string{"192.168.1.1:43184", "localhost:43184"} {
		listener, _, err := openModelRelay("127.0.0.1:0", target, "192.168.128.0/24")
		if listener != nil {
			_ = listener.Close()
		}
		if err == nil {
			t.Fatalf("non-loopback target %q accepted", target)
		}
	}
}
