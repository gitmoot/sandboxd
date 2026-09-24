// Package envd serves the small, authenticated E2B guest API Gitmoot uses.
package envd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

const (
	maxStartBytes    = 1 << 20
	maxOutputChunk   = 64 << 10
	defaultMaxUpload = 512 << 20
	defaultMaxOutput = 64 << 20
	connectMediaType = "application/connect+json"
)

// Authorizer checks the sandbox-scoped data-plane capability and live state.
type Authorizer interface {
	Authorize(sandboxID, token string) bool
	Abort(context.Context, string, string) error
}

// Handler exposes only file upload and process start for an owned VM.
type Handler struct {
	Driver     vm.Driver
	Authorizer Authorizer
	Domain     string
	// GatewayHost permits E2B's header-routed data plane on one private
	// hostname instead of requiring wildcard sandbox DNS and certificates.
	GatewayHost    string
	MaxUploadBytes int64
	MaxOutputBytes int64
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Driver == nil || h.Authorizer == nil {
		http.Error(w, "guest service unavailable", http.StatusServiceUnavailable)
		return
	}
	id, ok := sandboxHostID(r.Host, h.Domain)
	if h.GatewayHost != "" && strings.EqualFold(hostName(r.Host), hostName(h.GatewayHost)) {
		headerID := r.Header.Get("E2b-Sandbox-Id")
		if r.Header.Get("E2b-Sandbox-Port") == "49983" && validSandboxID(headerID) {
			id, ok = headerID, true
		}
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	token := r.Header.Get("X-Access-Token")
	if token == "" || !h.Authorizer.Authorize(id, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/files":
		h.upload(w, r, id, token)
	case "/process.Process/Start":
		h.start(w, r, id, token)
	default:
		http.NotFound(w, r)
	}
}

func hostName(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return strings.TrimSuffix(host, ".")
}

func sandboxHostID(host, domain string) (string, bool) {
	host = strings.ToLower(hostName(host))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return "", false
	}
	prefix := "49983-"
	suffix := "." + domain
	if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(host, prefix), suffix)
	return id, validSandboxID(id)
}

func validSandboxID(id string) bool {
	return id != "" && len(id) <= 128 && strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func (h *Handler) upload(w http.ResponseWriter, r *http.Request, id, token string) {
	if r.Method != http.MethodPost || r.URL.Query().Get("username") != "user" || r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "invalid upload request", http.StatusBadRequest)
		return
	}
	guestPath := r.URL.Query().Get("path")
	if !safeGuestPath(guestPath) {
		http.Error(w, "invalid guest path", http.StatusBadRequest)
		return
	}
	limit := h.MaxUploadBytes
	if limit <= 0 {
		limit = defaultMaxUpload
	}
	if r.ContentLength > limit {
		http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
		return
	}
	file, err := os.CreateTemp("", "sandboxd-upload-*")
	if err != nil {
		http.Error(w, "upload unavailable", http.StatusServiceUnavailable)
		return
	}
	defer os.Remove(file.Name())
	defer file.Close()
	amount, err := io.Copy(file, io.LimitReader(r.Body, limit+1))
	if err != nil {
		http.Error(w, "upload failed", http.StatusBadRequest)
		return
	}
	if amount > limit {
		http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := file.Close(); err != nil {
		http.Error(w, "upload failed", http.StatusServiceUnavailable)
		return
	}
	if err := h.Driver.CopyIn(r.Context(), id, file.Name(), guestPath); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = h.Authorizer.Abort(cleanup, id, token)
		cancel()
		http.Error(w, "guest upload failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{}")
}

func safeGuestPath(p string) bool {
	if !path.IsAbs(p) || path.Clean(p) != p || !strings.HasPrefix(p, "/home/user/") || strings.ContainsAny(p, ":\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

type startRequest struct {
	Process struct {
		Command string            `json:"cmd"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"envs"`
		Dir     string            `json:"cwd"`
	} `json:"process"`
	Stdin bool `json:"stdin"`
}

func (h *Handler) start(w http.ResponseWriter, r *http.Request, id, token string) {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != connectMediaType || r.Header.Get("connect-protocol-version") != "1" {
		http.Error(w, "invalid process request", http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusServiceUnavailable)
		return
	}
	var header [5]byte
	if _, err := io.ReadFull(r.Body, header[:]); err != nil || header[0] != 0 || binary.BigEndian.Uint32(header[1:]) > maxStartBytes {
		http.Error(w, "invalid process frame", http.StatusBadRequest)
		return
	}
	payload := make([]byte, int(binary.BigEndian.Uint32(header[1:])))
	if r.ContentLength != int64(5+len(payload)) {
		http.Error(w, "invalid process frame length", http.StatusBadRequest)
		return
	}
	if _, err := io.ReadFull(r.Body, payload); err != nil {
		http.Error(w, "invalid process frame", http.StatusBadRequest)
		return
	}
	var request startRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&request); err != nil || decoder.Decode(new(any)) != io.EOF || request.Stdin || strings.TrimSpace(request.Process.Command) == "" || len(request.Process.Args) > 512 || !safeGuestDir(request.Process.Dir) {
		http.Error(w, "invalid process payload", http.StatusBadRequest)
		return
	}
	if len(request.Process.Env) > 256 {
		http.Error(w, "too many environment values", http.StatusBadRequest)
		return
	}
	for key := range request.Process.Env {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			http.Error(w, "invalid environment name", http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("Content-Type", connectMediaType)
	w.Header().Set("connect-protocol-version", "1")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	limit := h.MaxOutputBytes
	if limit <= 0 {
		limit = defaultMaxOutput
	}
	stream := &eventWriter{w: w, flush: flusher, outputLimit: limit}
	started := false
	command := vm.Command{Args: append([]string{request.Process.Command}, request.Process.Args...), Dir: request.Process.Dir, Env: request.Process.Env, User: "user"}
	command.OnStart = func(pid int) {
		if pid > 0 {
			started = true
			_ = stream.event(map[string]any{"event": map[string]any{"start": map[string]int{"pid": pid}}})
		}
	}
	code, err := h.Driver.Run(r.Context(), id, command, &outputWriter{stream: stream, kind: "stdout"}, &outputWriter{stream: stream, kind: "stderr"})
	stream.outputMu.Lock()
	outputErr := stream.outputErr
	stream.outputMu.Unlock()
	if err != nil || outputErr != nil || !started {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = h.Authorizer.Abort(cleanup, id, token)
		cancel()
		_ = stream.frame(2, []byte(`{"error":{"code":"unavailable","message":"guest execution failed"}}`))
		return
	}
	if err := stream.event(map[string]any{"event": map[string]any{"end": map[string]any{"exitCode": code, "exited": true}}}); err != nil {
		return
	}
	_ = stream.frame(2, []byte("{}"))
}

func safeGuestDir(dir string) bool {
	return dir == "" || dir == "/home/user" || safeGuestPath(dir)
}

type eventWriter struct {
	mu          sync.Mutex
	outputMu    sync.Mutex
	w           http.ResponseWriter
	flush       http.Flusher
	outputBytes int64
	outputErr   error
	outputLimit int64
}

func (s *eventWriter) event(event any) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return s.frame(0, body)
}

func (s *eventWriter) frame(flag byte, payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var header [5]byte
	header[0] = flag
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := s.w.Write(header[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(payload); err != nil {
		return err
	}
	s.flush.Flush()
	return nil
}

type outputWriter struct {
	stream *eventWriter
	kind   string
}

func (o *outputWriter) Write(p []byte) (int, error) {
	o.stream.outputMu.Lock()
	defer o.stream.outputMu.Unlock()
	if o.stream.outputErr != nil {
		return 0, o.stream.outputErr
	}
	for offset := 0; offset < len(p); {
		end := min(offset+maxOutputChunk, len(p))
		if int64(end-offset) > o.stream.outputLimit-o.stream.outputBytes {
			o.stream.outputErr = errors.New("guest output exceeds stream limit")
			return offset, o.stream.outputErr
		}
		if err := o.stream.event(map[string]any{"event": map[string]any{"data": map[string][]byte{o.kind: p[offset:end]}}}); err != nil {
			o.stream.outputErr = err
			return offset, err
		}
		o.stream.outputBytes += int64(end - offset)
		offset = end
	}
	return len(p), nil
}
