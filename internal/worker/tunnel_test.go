package worker

import (
	"context"
	"io"
	"net"
	"sync"
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

type observedTunnelDriver struct {
	*tunnelDriver
	closed chan struct{}
}

type observedTunnelConn struct {
	*net.TCPConn
	closed chan struct{}
	once   sync.Once
}

func (c *observedTunnelConn) Close() error {
	err := c.TCPConn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func (d *observedTunnelDriver) DialTunnel(ctx context.Context, id string, port int) (net.Conn, error) {
	conn, err := d.tunnelDriver.DialTunnel(ctx, id, port)
	if err != nil {
		return nil, err
	}
	return &observedTunnelConn{TCPConn: conn.(*net.TCPConn), closed: d.closed}, nil
}

func TestTunnelRemoteCloseAfterDirectionalEOF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	driver := &observedTunnelDriver{
		tunnelDriver: &tunnelDriver{fakeDriver: newFake(), target: listener.Addr().String()},
		closed:       make(chan struct{}),
	}
	_, server := serve(t, driver)
	client := enrolled(t, server.URL, 1)
	conn, err := client.DialTunnel(context.Background(), "sandboxd-00000000000000000000000000000e2b", 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	guest, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	_ = guest.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(guest); err != nil || len(data) != 0 {
		t.Fatalf("guest directional EOF: %q %v", data, err)
	}
	// Keep the guest open and idle after its read EOF. Closing the upgraded
	// client transport must release the worker's guest connection anyway.
	_ = conn.Close()
	select {
	case <-driver.closed:
	case <-time.After(time.Second):
		t.Fatal("worker retained guest connection after client transport close")
	}
}
