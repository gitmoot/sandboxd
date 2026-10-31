//go:build linux

package guestagent

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// Use the actual accepted-socket wrapper, not net.Pipe's different close
// semantics. Speak the wire protocol so this test also compiles on old agents.
func TestTunnelDirectionalEOF(t *testing.T) {
	for _, first := range []string{"host", "guest", "host-disconnect"} {
		t.Run(first, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			payload := bytes.Repeat([]byte("\x00SSH\xff"), 10000)
			release := make(chan struct{})
			defer close(release)
			upstreamDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					upstreamDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if first == "guest" {
					_, err = conn.Write(payload)
					if err == nil {
						err = conn.(*net.TCPConn).CloseWrite()
					}
				}
				got, readErr := io.ReadAll(conn)
				if err == nil {
					err = readErr
				}
				if err == nil && !bytes.Equal(got, payload) {
					err = io.ErrUnexpectedEOF
				}
				if first == "host" && err == nil {
					_, err = conn.Write(payload)
				}
				upstreamDone <- err
				if first == "host-disconnect" {
					// Stay open and idle so the guest cannot release the bridge.
					<-release
				}
			}()
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fds[0]), "tunnel-host")
			host, err := net.FileConn(file)
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			_ = host.SetDeadline(time.Now().Add(5 * time.Second))
			guest, err := SocketConn(fds[1], "tunnel-guest")
			if err != nil {
				t.Fatal(err)
			}
			server := testServer(t)
			server.DialHost = "127.0.0.1"
			done := make(chan struct{})
			go func() { server.ServeConn(guest); close(done) }()
			if err := WriteRequest(host, Request{Op: "tunnel", Port: listener.Addr().(*net.TCPAddr).Port}); err != nil {
				t.Fatal(err)
			}
			kind, data, err := ReadFrame(host)
			var result Result
			if err != nil || kind != FrameResult {
				t.Fatalf("ack: %d %v", kind, err)
			}
			if err := json.Unmarshal(data, &result); err != nil || result.Error != "" {
				t.Fatalf("ack result: %s %v", result.Error, err)
			}
			send := func() {
				for start := 0; start < len(payload); start += 8192 {
					if err := WriteFrame(host, 0, payload[start:min(start+8192, len(payload))]); err != nil {
						t.Fatal(err)
					}
				}
				if err := WriteFrame(host, 1, nil); err != nil {
					t.Fatal(err)
				}
			}
			receive := func() {
				var got []byte
				for {
					kind, data, err := ReadFrame(host)
					if err != nil {
						t.Fatal(err)
					}
					if kind == 1 {
						if len(data) != 0 {
							t.Fatal("EOF payload")
						}
						break
					}
					if kind != 0 {
						t.Fatalf("frame kind=%d", kind)
					}
					got = append(got, data...)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("reverse payload differs: got %d want %d", len(got), len(payload))
				}
			}
			if first == "host-disconnect" {
				send()
				if err := <-upstreamDone; err != nil {
					t.Fatal(err)
				}
				_ = host.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("guest agent retained bridge after host transport close")
				}
				return
			}
			if first == "host" {
				send()
				receive()
			} else {
				receive()
				send()
			}
			if err := <-upstreamDone; err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("guest bridge retained after both EOFs")
			}
		})
	}
}
