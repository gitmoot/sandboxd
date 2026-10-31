package worker

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type tunnelDriver struct {
	*fakeDriver
	target string
}

func (d *tunnelDriver) DialTunnel(ctx context.Context, _ string, _ int) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}

func TestTunnelRemoteDirectionalEOF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(c)
		if err == nil {
			_, err = c.Write(append([]byte("response:"), data...))
		}
		done <- err
	}()
	driver := &tunnelDriver{fakeDriver: newFake(), target: listener.Addr().String()}
	_, server := serve(t, driver)
	client := enrolled(t, server.URL, 1)
	// Keep the test old-code compatible so absence of the new transport is a
	// behavioral failure, not a compile failure in the regression proof.
	dialer, ok := any(client).(interface {
		DialTunnel(context.Context, string, int) (net.Conn, error)
	})
	if !ok {
		t.Fatal("worker client does not support directional tunnel transport")
	}
	conn, err := dialer.DialTunnel(context.Background(), "sandboxd-00000000000000000000000000000e2b", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "SSH\x00binary\xff"); err != nil {
		t.Fatal(err)
	}
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("missing CloseWrite")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := io.ReadAll(conn)
		result <- struct {
			data []byte
			err  error
		}{data, err}
	}()
	select {
	case got := <-result:
		if got.err != nil || string(got.data) != "response:SSH\x00binary\xff" {
			t.Fatalf("reverse response after EOF: %q %v", got.data, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote bridge lost directional EOF")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
