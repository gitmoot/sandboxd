//go:build linux

package guestagent

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the write helper, as the agent binary does.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "guestagent-write-helper" {
		if err := RunWriteHelper(os.Args[2], os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		Env:         []string{"PATH=/usr/bin:/bin", "HOME=/image-home", "KEEP=image"},
		Dir:         t.TempDir(),
		WriteHelper: []string{os.Args[0], "guestagent-write-helper"},
		WaitDelay:   time.Second,
	}
}

// connect returns the host end of a connection served by s, after the
// Firecracker-style handshake.
func connect(t *testing.T, s *Server) net.Conn {
	t.Helper()
	host, guest := net.Pipe()
	go func() {
		line, err := bufio.NewReader(io.LimitReader(guest, 13)).ReadString('\n')
		if err != nil || line != "CONNECT 1024\n" {
			_ = guest.Close()
			return
		}
		_, _ = io.WriteString(guest, "OK 1073741824\n")
		s.ServeConn(guest)
	}()
	if err := Handshake(host, Port); err != nil {
		t.Fatal(err)
	}
	return host
}

func TestExecStreamsOutputAndExitCode(t *testing.T) {
	s := testServer(t)
	var stdout, stderr bytes.Buffer
	started := 0
	code, err := Exec(context.Background(), connect(t, s), Request{
		Args: []string{"sh", "-c", `echo "$KEEP $HOME $NEW"; pwd; echo err >&2; exit 3`},
		Env:  map[string]string{"HOME": "/home/user", "NEW": "req"},
	}, &stdout, &stderr, func(id int) { started = id })
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || started <= 0 {
		t.Fatalf("code=%d started=%d", code, started)
	}
	if want := "image /home/user req\n" + s.Dir + "\n"; stdout.String() != want || stderr.String() != "err\n" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestExecResolvesOnRequestPath(t *testing.T) {
	s := testServer(t)
	bin := t.TempDir()
	script := filepath.Join(bin, "only-here")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho found\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code, err := Exec(context.Background(), connect(t, s), Request{Args: []string{"only-here"}, Env: map[string]string{"PATH": bin + ":/usr/bin:/bin"}}, &stdout, &stderr, nil)
	if err != nil || code != 0 || stdout.String() != "found\n" {
		t.Fatalf("code=%d err=%v stdout=%q", code, err, stdout.String())
	}
	stdout.Reset()
	code, err = Exec(context.Background(), connect(t, s), Request{Args: []string{"only-here"}}, &stdout, &stderr, nil)
	if err != nil || code != 127 || !strings.Contains(stderr.String(), "command not found") {
		t.Fatalf("missing command: code=%d err=%v stderr=%q", code, err, stderr.String())
	}
}

func TestExecRejectsUnsafeRequests(t *testing.T) {
	s := testServer(t)
	for _, request := range []Request{
		{Args: nil},
		{Args: []string{"true"}, Dir: "relative"},
		{Args: []string{"true"}, Dir: "/a/../b"},
		{Args: []string{"true"}, Env: map[string]string{"BAD-NAME": "x"}},
		{Args: []string{"tr\x00ue"}},
	} {
		if _, err := Exec(context.Background(), connect(t, s), request, io.Discard, io.Discard, nil); err == nil {
			t.Errorf("request %+v was accepted", request)
		}
	}
}

// Canceling the host side kills the command's whole process group in the
// guest, including children that hold its output open.
func TestExecCancelKillsProcessGroup(t *testing.T) {
	s := testServer(t)
	marker := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := Exec(ctx, connect(t, s), Request{Args: []string{"sh", "-c", `sleep 300 & echo $! > ` + marker + `; wait`}}, io.Discard, io.Discard, nil)
		done <- err
	}()
	var pid int
	for deadline := time.Now().Add(5 * time.Second); pid == 0; {
		data, _ := os.ReadFile(marker)
		fmt.Sscanf(string(data), "%d", &pid)
		if time.Now().After(deadline) {
			t.Fatal("child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil || strings.Contains(string(data), ") Z ") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background child survived cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWriteCreatesPrivateParentsAndFile(t *testing.T) {
	s := testServer(t)
	dest := filepath.Join(t.TempDir(), "a", "b", "file")
	payload := strings.Repeat("x", 3<<20)
	if err := Write(context.Background(), connect(t, s), dest, int64(len(payload)), strings.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != payload {
		t.Fatalf("read back %d bytes, %v", len(data), err)
	}
	for path, mode := range map[string]os.FileMode{dest: 0o600, filepath.Dir(dest): 0o700, filepath.Dir(filepath.Dir(dest)): 0o700} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, %v; want %v", path, info.Mode().Perm(), err, mode)
		}
	}
	if err := Write(context.Background(), connect(t, s), "relative", 1, strings.NewReader("x")); err == nil {
		t.Fatal("relative destination accepted")
	}
}

// A stream that ends before the result frame is a transport failure, never
// an exit status.
func TestTruncatedStreamIsAnError(t *testing.T) {
	host, guest := net.Pipe()
	go func() {
		reader := bufio.NewReader(guest)
		_, _ = ReadRequest(reader)
		_ = WriteJSONFrame(guest, FrameStarted, Started{ID: 1})
		_ = WriteFrame(guest, FrameStdout, []byte("partial"))
		_, _ = guest.Write([]byte{FrameResult, 0, 0, 0, 9, '{'})
		_ = guest.Close()
	}()
	var stdout bytes.Buffer
	if _, err := Exec(context.Background(), host, Request{Args: []string{"x"}}, &stdout, io.Discard, nil); err == nil {
		t.Fatal("truncated stream reported success")
	}
}

func TestHandshakeRejectsRefusal(t *testing.T) {
	host, guest := net.Pipe()
	go func() {
		_, _ = bufio.NewReader(guest).ReadString('\n')
		_, _ = io.WriteString(guest, "NO\n")
	}()
	if err := Handshake(host, Port); err == nil {
		t.Fatal("refused handshake accepted")
	}
}
