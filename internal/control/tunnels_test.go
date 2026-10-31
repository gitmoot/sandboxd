package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/envd"
	"github.com/gitmoot/sandboxd/internal/vm"
)

type tunnelTestDriver struct {
	*fakeDriver
	target string
}

func (d *tunnelTestDriver) DialTunnel(ctx context.Context, _ string, _ int) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}

type testLease struct {
	ID      string    `json:"leaseID"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expiresAt"`
}

type tunnelFixture struct {
	service  *Service
	server   *httptest.Server
	listener net.Listener
	id       string
	close    func()
}

func newTunnelFixture(t *testing.T, serve func(net.Conn)) tunnelFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _ = conn.SetDeadline(time.Now().Add(10 * time.Second)); serve(conn) }()
		}
	}()
	driver := &tunnelTestDriver{fakeDriver: &fakeDriver{instances: make(map[string]vm.Instance)}, target: listener.Addr().String()}
	cfg := mixedConfig(map[string]Template{"base": {Image: "guest", Profile: ProfileE2B, Ports: []int{22}, EnvdVersion: "0.9.0"}}, 2)
	cfg.MaxTTL = time.Hour
	service, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var closeOnce sync.Once
	closeService := func() { closeOnce.Do(func() { _ = service.Close() }) }
	t.Cleanup(closeService)
	created := request(t, service, http.MethodPost, "/v2/sandboxes", map[string]any{"templateID": "base", "timeout": 600})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var body struct {
		ID string `json:"sandboxID"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	proxy := envd.NewProxy(service, "sandbox.test", "127.0.0.1")
	proxy.MaxPortStreams = 1
	handler := &envd.Handler{Driver: service.Guests(), Authorizer: service}
	server := httptest.NewServer(envd.Routes(handler, proxy, service.Handler()))
	t.Cleanup(server.Close)
	return tunnelFixture{service, server, listener, body.ID, closeService}
}

func (f tunnelFixture) mint(t *testing.T, ttl int) testLease {
	t.Helper()
	response := request(t, f.service, "POST", "/sandboxes/"+f.id+"/tunnel-leases", map[string]int{"port": 22, "ttl": ttl})
	if response.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", response.Code, response.Body.String())
	}
	var lease testLease
	if err := json.Unmarshal(response.Body.Bytes(), &lease); err != nil {
		t.Fatal(err)
	}
	return lease
}

func (f tunnelFixture) connect(t *testing.T, target, token, extra, initial string) (*net.TCPConn, *bufio.Reader, int) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", strings.TrimPrefix(f.server.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := raw.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nE2b-Tunnel-Access-Token: %s\r\n%s\r\n%s", target, target, token, extra, initial)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		_ = conn.Close()
	}
	return conn, reader, response.StatusCode
}

func TestTunnelCONNECTHalfCloseAndIsolation(t *testing.T) {
	f := newTunnelFixture(t, func(conn net.Conn) {
		data, err := io.ReadAll(conn)
		if err == nil {
			_, _ = conn.Write(append([]byte("after EOF:"), data...))
		}
	})
	lease := f.mint(t, 300)
	for _, test := range []struct {
		name, target, token string
		status              int
	}{
		{"wrong token", f.id + ":22", "wrong", 403},
		{"wrong port", f.id + ":23", lease.Token, 403},
		{"arbitrary host", "127.0.0.1:22", lease.Token, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, status := f.connect(t, test.target, test.token, "", "")
			if status != test.status {
				t.Fatalf("status=%d want %d", status, test.status)
			}
		})
	}
	second := request(t, f.service, "POST", "/v2/sandboxes", map[string]any{"templateID": "base", "timeout": 600})
	if second.Code != 201 {
		t.Fatalf("second sandbox: %s", second.Body.String())
	}
	var other struct {
		ID string `json:"sandboxID"`
	}
	_ = json.Unmarshal(second.Body.Bytes(), &other)
	if _, _, status := f.connect(t, other.ID+":22", lease.Token, "", ""); status != 403 {
		t.Fatalf("cross-sandbox token status=%d", status)
	}
	// Pipelined bytes following CONNECT must survive the HTTP parser buffer.
	conn, reader, status := f.connect(t, f.id+":22", lease.Token, "X-API-Key: must-not-reach-guest\r\n", "first\x00")
	if status != 200 {
		t.Fatalf("CONNECT=%d", status)
	}
	if _, _, status := f.connect(t, f.id+":22", lease.Token, "", ""); status != 429 {
		t.Fatalf("stream cap=%d", status)
	}
	payload := bytes.Repeat([]byte("\xffssh\x00"), 40000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("after EOF:first\x00"), payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("response after client EOF differs: got %d bytes want %d", len(got), len(want))
	}
	if response := request(t, f.service, "GET", "/sandboxes/"+f.id, nil); response.Code != 200 {
		t.Fatalf("disconnect destroyed VM: %d", response.Code)
	}
}

func TestTunnelRenewRevokeAndExpiredReconnect(t *testing.T) {
	received := make(chan error, 1)
	f := newTunnelFixture(t, func(conn net.Conn) {
		_, _ = conn.Write([]byte("guest EOF"))
		_ = conn.(*net.TCPConn).CloseWrite()
		data := make([]byte, len("still receiving"))
		_, err := io.ReadFull(conn, data)
		if err == nil && string(data) != "still receiving" {
			err = fmt.Errorf("wrong reverse bytes: %q", data)
		}
		received <- err
		_, _ = io.Copy(io.Discard, conn)
	})
	lease := f.mint(t, 1)
	conn, reader, status := f.connect(t, f.id+":22", lease.Token, "", "")
	if status != 200 {
		t.Fatalf("CONNECT=%d", status)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "guest EOF" {
		t.Fatalf("guest EOF: %q %v", data, err)
	}
	renew := request(t, f.service, "POST", "/sandboxes/"+f.id+"/tunnel-leases/"+lease.ID+"/renew", map[string]int{"ttl": 300})
	if renew.Code != 200 {
		t.Fatalf("renew: %d %s", renew.Code, renew.Body.String())
	}
	var renewed testLease
	_ = json.Unmarshal(renew.Body.Bytes(), &renewed)
	if renewed.ID != lease.ID || renewed.Token != lease.Token || !renewed.Expires.After(lease.Expires) {
		t.Fatalf("renew changed identity or failed to extend: %+v", renewed)
	}
	// Wait past the ORIGINAL expiry, not an arbitrary sleep: the active stream
	// must still accept reverse traffic after the guest has half-closed.
	time.Sleep(max(0, time.Until(lease.Expires.Add(30*time.Millisecond))))
	if _, err := conn.Write([]byte("still receiving")); err != nil {
		t.Fatalf("renewed stream closed: %v", err)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("renewed stream did not deliver reverse bytes")
	}
	revoke := request(t, f.service, "DELETE", "/sandboxes/"+f.id+"/tunnel-leases/"+lease.ID, nil)
	if revoke.Code != 204 {
		t.Fatalf("revoke=%d", revoke.Code)
	}
	if _, _, status := f.connect(t, f.id+":22", lease.Token, "", ""); status != 403 {
		t.Fatalf("revoked reconnect=%d", status)
	}
	if response := request(t, f.service, "POST", "/sandboxes/"+f.id+"/tunnel-leases/"+lease.ID+"/renew", map[string]int{"ttl": 300}); response.Code != 403 {
		t.Fatalf("revived revoked lease=%d", response.Code)
	}
	if response := request(t, f.service, "GET", "/sandboxes/"+f.id, nil); response.Code != 200 {
		t.Fatalf("revocation destroyed VM=%d", response.Code)
	}
	expired := f.mint(t, 1)
	time.Sleep(max(0, time.Until(expired.Expires.Add(30*time.Millisecond))))
	if response := request(t, f.service, "POST", "/sandboxes/"+f.id+"/tunnel-leases/"+expired.ID+"/renew", map[string]int{"ttl": 300}); response.Code != 403 {
		t.Fatalf("revived expired lease=%d", response.Code)
	}
	if _, _, status := f.connect(t, f.id+":22", expired.Token, "", ""); status != 403 {
		t.Fatalf("expired reconnect=%d", status)
	}
}

func TestTunnelRevocationAndDestroyCloseActiveStream(t *testing.T) {
	for _, action := range []string{"revoke", "destroy", "shutdown"} {
		t.Run(action, func(t *testing.T) {
			f := newTunnelFixture(t, func(conn net.Conn) { _, _ = io.Copy(io.Discard, conn) })
			lease := f.mint(t, 300)
			_, reader, status := f.connect(t, f.id+":22", lease.Token, "", "")
			if status != 200 {
				t.Fatalf("CONNECT=%d", status)
			}
			switch action {
			case "revoke":
				if response := request(t, f.service, "DELETE", "/sandboxes/"+f.id+"/tunnel-leases/"+lease.ID, nil); response.Code != 204 {
					t.Fatal(response.Code)
				}
			case "destroy":
				if response := request(t, f.service, "DELETE", "/sandboxes/"+f.id, nil); response.Code != 204 {
					t.Fatal(response.Code)
				}
			case "shutdown":
				f.close()
			}
			_, err := reader.ReadByte()
			if err == nil {
				t.Fatal("stream stayed readable after teardown")
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatalf("teardown did not close stream: %v", err)
			}
		})
	}
}
