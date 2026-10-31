package tunnel

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestBridgeTransportCloseAfterDirectionalEOF(t *testing.T) {
	for _, direction := range []string{"client", "upstream"} {
		t.Run(direction, func(t *testing.T) {
			clientWire, clientPeer := net.Pipe()
			upstreamWire, upstreamPeer := net.Pipe()
			client, upstream := New(clientWire, nil), New(upstreamWire, nil)
			first, second := New(clientPeer, nil), New(upstreamPeer, nil)
			defer first.Close()
			defer second.Close()
			defer client.Close()
			defer upstream.Close()
			_ = first.SetDeadline(time.Now().Add(5 * time.Second))
			_ = second.SetDeadline(time.Now().Add(5 * time.Second))
			if direction == "upstream" {
				first, second = second, first
			}
			done := make(chan struct{})
			go func() { Bridge(client, client, upstream); close(done) }()
			sent := make(chan error, 1)
			go func() { sent <- first.CloseWrite() }()
			var one [1]byte
			if n, err := second.Read(one[:]); n != 0 || err != io.EOF {
				t.Fatalf("directional EOF: n=%d err=%v", n, err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			// Directional EOF must leave reverse traffic usable, not cancel it.
			go func() { _, err := second.Write([]byte{42}); sent <- err }()
			if _, err := io.ReadFull(first, one[:]); err != nil || one[0] != 42 {
				t.Fatalf("reverse data after EOF: %v %v", one, err)
			}
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			// The opposite peer stays open and idle: only this transport close
			// can release the bridge and its downstream resources.
			_ = first.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("transport close after directional EOF retained bridge")
			}
			if _, err := second.Write([]byte{1}); err == nil {
				t.Fatal("bridge left the opposite transport open")
			}
		})
	}
}
