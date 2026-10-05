package guestagent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var envName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9]*$`)

// Server executes requests inside the guest. Commands and file writes run with
// Credential (the guest user, uid/gid 1000); a nil Credential keeps the
// agent's own identity and exists only for tests.
type Server struct {
	// Env is the image's base environment ("KEY=VALUE"); request variables
	// replace entries of the same name, as E2B's envd applies them.
	Env []string
	// Dir is the working directory when a request names none.
	Dir        string
	Credential *syscall.Credential
	// WriteHelper is the argv prefix of the write helper process; the
	// destination path is appended. The helper must call RunWriteHelper.
	WriteHelper []string
	// WaitDelay bounds how long output is drained after the command exits
	// while background children keep its pipes open.
	WaitDelay time.Duration
	// EnvdAddr is the guest-local envd address OpEnvd bridges to, empty when
	// the guest runs no envd.
	EnvdAddr string
	// DiskPath is a path on the guest's writable filesystem, reported by
	// OpDisk; empty disables OpDisk.
	DiskPath string

	next atomic.Int64
}

// ServeConn handles exactly one request and closes conn.
func (s *Server) ServeConn(conn io.ReadWriteCloser) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := ReadRequest(reader)
	if err != nil {
		_ = WriteJSONFrame(conn, FrameResult, Result{Error: err.Error()})
		return
	}
	var result Result
	switch request.Op {
	case OpPing:
		result = Result{}
	case OpExec:
		result = s.exec(conn, reader, request)
	case OpWrite:
		result = s.write(reader, request)
	case OpEnvd:
		if result = s.envd(conn, reader); result.Error == "" {
			return
		}
	case OpDisk:
		result = s.disk()
	default:
		result = Result{Error: fmt.Sprintf("unknown guest agent operation %q", request.Op)}
	}
	_ = WriteJSONFrame(conn, FrameResult, result)
}

// envd connects to envd and, once the host has its acknowledgement, copies
// bytes both ways until either side ends; then both are closed. An empty
// Error means the bridge ran and nothing more may be written to conn.
func (s *Server) envd(conn io.ReadWriteCloser, reader *bufio.Reader) Result {
	if s.EnvdAddr == "" {
		return Result{Error: "this guest runs no envd"}
	}
	upstream, err := net.DialTimeout("tcp", s.EnvdAddr, 5*time.Second)
	if err != nil {
		return Result{Error: fmt.Sprintf("envd unreachable: %v", err)}
	}
	defer upstream.Close()
	if err := WriteJSONFrame(conn, FrameResult, Result{}); err != nil {
		return Result{}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, reader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = upstream.Close()
	_ = conn.Close()
	<-done
	return Result{}
}

func (s *Server) disk() Result {
	if s.DiskPath == "" {
		return Result{Error: "guest disk reporting is not configured"}
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.DiskPath, &stat); err != nil {
		return Result{Error: fmt.Sprintf("statfs: %v", err)}
	}
	size := uint64(stat.Bsize)
	total := stat.Blocks * size
	return Result{DiskTotal: total, DiskUsed: total - stat.Bfree*size}
}

func validPath(path string) bool {
	return strings.HasPrefix(path, "/") && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

// frameWriter serializes stdout and stderr chunks onto the connection.
type frameWriter struct {
	mu   *sync.Mutex
	conn io.Writer
	kind byte
}

func (w frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for offset := 0; offset < len(p); {
		end := min(offset+MaxFrameBytes, len(p))
		if err := WriteFrame(w.conn, w.kind, p[offset:end]); err != nil {
			return offset, err
		}
		offset = end
	}
	return len(p), nil
}

// mergeEnv returns base with every request variable replacing (or adding)
// the entry of the same name.
func mergeEnv(base []string, overlay map[string]string) []string {
	merged := make([]string, 0, len(base)+len(overlay))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := overlay[name]; !replaced {
			merged = append(merged, entry)
		}
	}
	keys := make([]string, 0, len(overlay))
	for key := range overlay {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		merged = append(merged, key+"="+overlay[key])
	}
	return merged
}

func lookupEnv(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if key, v, ok := strings.Cut(entry, "="); ok && key == name {
			value = v
		}
	}
	return value
}

// lookPath resolves a bare command name on the request's PATH (not the
// agent's), as execvp in the guest user's shell would.
func lookPath(name string, env []string, dir string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, entry := range filepath.SplitList(lookupEnv(env, "PATH")) {
		if entry == "" {
			entry = "."
		}
		candidate := filepath.Join(entry, name)
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(dir, candidate)
		}
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func (s *Server) exec(conn io.Writer, reader *bufio.Reader, request Request) Result {
	if len(request.Args) == 0 || request.Args[0] == "" {
		return Result{Error: "empty guest command"}
	}
	for _, arg := range request.Args {
		if strings.ContainsRune(arg, 0) {
			return Result{Error: "NUL in guest command"}
		}
	}
	for key, value := range request.Env {
		if !envName.MatchString(key) || strings.ContainsRune(value, 0) {
			return Result{Error: fmt.Sprintf("unsafe guest environment variable %q", key)}
		}
	}
	dir := request.Dir
	if dir == "" {
		dir = s.Dir
	}
	if !validPath(dir) {
		return Result{Error: fmt.Sprintf("unsafe guest working directory %q", dir)}
	}
	var mu sync.Mutex
	stdout := frameWriter{mu: &mu, conn: conn, kind: FrameStdout}
	stderr := frameWriter{mu: &mu, conn: conn, kind: FrameStderr}
	mu.Lock()
	err := WriteJSONFrame(conn, FrameStarted, Started{ID: int(s.next.Add(1))})
	mu.Unlock()
	if err != nil {
		return Result{Error: err.Error()}
	}
	env := mergeEnv(s.Env, request.Env)
	path, err := lookPath(request.Args[0], env, dir)
	if err != nil {
		fmt.Fprintf(stderr, "sandboxd-agent: %s: command not found\n", request.Args[0])
		return Result{Code: 127}
	}
	cmd := &exec.Cmd{Path: path, Args: request.Args, Env: env, Dir: dir, Stdout: stdout, Stderr: stderr, WaitDelay: s.WaitDelay}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: s.Credential}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "sandboxd-agent: %s: %v\n", request.Args[0], err)
		if errors.Is(err, os.ErrNotExist) {
			return Result{Code: 127}
		}
		return Result{Code: 126}
	}
	// The host never writes after the request; a read returning means it
	// closed or canceled the request, so the whole process group is killed.
	finished := make(chan struct{})
	var killMu sync.Mutex
	go func() {
		_, _ = reader.ReadByte()
		killMu.Lock()
		defer killMu.Unlock()
		select {
		case <-finished:
		default:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}()
	err = cmd.Wait()
	killMu.Lock()
	close(finished)
	killMu.Unlock()
	if cmd.ProcessState == nil {
		return Result{Error: err.Error()}
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return Result{Error: "unknown guest wait status"}
	}
	if status.Signaled() {
		return Result{Code: 128 + int(status.Signal())}
	}
	return Result{Code: status.ExitStatus()}
}

func (s *Server) write(reader *bufio.Reader, request Request) Result {
	if !validPath(request.Path) || request.Path == "/" {
		return Result{Error: fmt.Sprintf("unsafe guest destination %q", request.Path)}
	}
	if request.Size < 0 || request.Size > MaxWriteBytes {
		return Result{Error: "guest write size out of range"}
	}
	if len(s.WriteHelper) == 0 {
		return Result{Error: "guest write helper is not configured"}
	}
	var stderr bytes.Buffer
	cmd := exec.Command(s.WriteHelper[0], append(s.WriteHelper[1:], request.Path)...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stderr = &limitedBuffer{buffer: &stderr, limit: 4096}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: s.Credential}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{Error: err.Error()}
	}
	if err := cmd.Start(); err != nil {
		return Result{Error: err.Error()}
	}
	_, copyErr := io.CopyN(stdin, reader, request.Size)
	closeErr := stdin.Close()
	waitErr := cmd.Wait()
	if waitErr != nil {
		return Result{Error: strings.TrimSpace(fmt.Sprintf("guest write failed: %v: %s", waitErr, stderr.String()))}
	}
	if err := errors.Join(copyErr, closeErr); err != nil {
		return Result{Error: fmt.Sprintf("guest write failed: %v", err)}
	}
	return Result{}
}

type limitedBuffer struct {
	buffer *bytes.Buffer
	limit  int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buffer.Len(); room > 0 {
		b.buffer.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// RunWriteHelper is the body of the write helper process, which already runs
// as the guest user: it creates missing parent directories (0700) and writes
// stdin to path (0600 when created), as `umask 077; mkdir -p; cat >` does.
func RunWriteHelper(path string, stdin io.Reader) error {
	if !validPath(path) || path == "/" {
		return fmt.Errorf("unsafe guest destination %q", path)
	}
	syscall.Umask(0o077)
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, stdin); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
