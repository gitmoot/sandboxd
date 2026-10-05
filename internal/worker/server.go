package worker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// Server exposes one local driver to the gateway over HTTP.
//
// It is meant to listen on loopback behind a private HTTPS proxy on the
// tailnet (Tailscale Serve), exactly like the control API. Every request must
// carry the worker's enrollment key as a bearer token; the server stores only
// the key's SHA-256 digest. Requests other than enrollment must carry the
// current lease in X-Sandboxd-Lease, and enrolling a newer lease cancels any
// Run or CopyIn still executing under an older one.
type Server struct {
	driver    vm.Driver
	meter     vm.ResourceMeter
	decl      Declaration
	keyHash   [sha256.Size]byte
	maxUpload int64

	mu          sync.Mutex
	lease       int64 // highest accepted lease; 0 until the first enrollment
	leaseCtx    context.Context
	leaseCancel context.CancelFunc
}

// NewServer exposes driver, declared as decl, to a gateway holding key, the
// per-worker enrollment secret (>= 16 bytes of visible ASCII).
func NewServer(driver vm.Driver, decl Declaration, key string) (*Server, error) {
	if driver == nil {
		return nil, errors.New("worker driver is required")
	}
	if err := decl.Validate(); err != nil {
		return nil, err
	}
	if err := validKey(key); err != nil {
		return nil, err
	}
	s := &Server{driver: driver, decl: decl.clone(), keyHash: sha256.Sum256([]byte(key)), maxUpload: maxUpload}
	s.meter, _ = driver.(vm.ResourceMeter)
	s.leaseCtx, s.leaseCancel = context.WithCancel(context.Background())
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, apiPrefix)
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	switch {
	case len(parts) == 1 && parts[0] == "enroll":
		if allow(w, r, http.MethodPost) {
			s.enroll(w, r)
		}
		return
	case len(parts) == 1 && parts[0] == "vms":
		switch r.Method {
		case http.MethodGet:
			s.leased(w, r, s.list)
		case http.MethodPost:
			s.leased(w, r, s.create)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	case len(parts) < 2 || len(parts) > 3 || parts[0] != "vms" || !vmIDPattern.MatchString(parts[1]):
		http.NotFound(w, r)
		return
	}
	id := parts[1]
	var method string
	var handle func(http.ResponseWriter, *http.Request, string, context.Context)
	switch {
	case len(parts) == 2:
		method, handle = http.MethodDelete, s.destroy
	case parts[2] == "files":
		method, handle = http.MethodPut, s.copyIn
	case parts[2] == "run":
		method, handle = http.MethodPost, s.run
	case parts[2] == "usage":
		method, handle = http.MethodGet, s.usage
	default:
		http.NotFound(w, r)
		return
	}
	if allow(w, r, method) {
		s.leased(w, r, func(w http.ResponseWriter, r *http.Request, leaseCtx context.Context) {
			handle(w, r, id, leaseCtx)
		})
	}
}

// authorized requires exactly one "Authorization: Bearer <key>" header whose
// key digest matches, compared in constant time.
func (s *Server) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	token, ok := strings.CutPrefix(values[0], "Bearer ")
	hash := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(s.keyHash[:], hash[:]) == 1 && ok
}

func allow(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var request enrollRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Lease < 1 {
		http.Error(w, "lease must be >= 1", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if request.Lease < s.lease {
		s.mu.Unlock()
		http.Error(w, staleMessage, http.StatusConflict)
		return
	}
	if request.Lease > s.lease {
		s.leaseCancel() // fence off everything still running under the old lease
		s.leaseCtx, s.leaseCancel = context.WithCancel(context.Background())
		s.lease = request.Lease
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.decl)
}

// leased admits a request only under exactly the current lease and hands the
// handler that lease's context, which is cancelled on re-enrollment.
func (s *Server) leased(w http.ResponseWriter, r *http.Request, handle func(http.ResponseWriter, *http.Request, context.Context)) {
	values := r.Header.Values(leaseHeader)
	if len(values) != 1 {
		http.Error(w, "exactly one "+leaseHeader+" header is required", http.StatusBadRequest)
		return
	}
	lease, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || lease < 1 {
		http.Error(w, "invalid "+leaseHeader+" header", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	current, leaseCtx := s.lease, s.leaseCtx
	s.mu.Unlock()
	if current == 0 || lease != current {
		http.Error(w, staleMessage, http.StatusConflict)
		return
	}
	handle(w, r, leaseCtx)
}

// fenced derives a context from the request that is also cancelled when the
// lease it was admitted under is superseded.
func fenced(r *http.Request, leaseCtx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(leaseCtx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, _ context.Context) {
	instances, err := s.driver.List(r.Context())
	if err != nil {
		driverFailed(w, "list")
		return
	}
	out := make([]instanceJSON, 0, len(instances))
	for _, instance := range instances {
		out = append(out, instanceJSON(instance))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, _ context.Context) {
	var request createRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	switch {
	case !vmIDPattern.MatchString(request.ID):
		http.Error(w, "invalid VM id", http.StatusBadRequest)
	case !s.declaresImage(request.Image):
		http.Error(w, "image is not declared by this worker", http.StatusBadRequest)
	case !slices.Contains(s.decl.Slots, request.Network):
		http.Error(w, "network is not a slot of this worker", http.StatusBadRequest)
	case request.CPUs != s.decl.CPUs || request.MemoryMiB != s.decl.MemoryMiB:
		http.Error(w, "VM shape differs from this worker's declaration", http.StatusBadRequest)
	default:
		instance, err := s.driver.Create(r.Context(), vm.Spec(request))
		if err != nil {
			driverFailed(w, "create")
			return
		}
		writeJSON(w, http.StatusCreated, instanceJSON(instance))
	}
}

func (s *Server) declaresImage(image string) bool {
	for _, declared := range s.decl.Templates {
		if declared == image {
			return true
		}
	}
	return false
}

func (s *Server) destroy(w http.ResponseWriter, r *http.Request, id string, _ context.Context) {
	if err := s.driver.Destroy(r.Context(), id); err != nil {
		driverFailed(w, "destroy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) copyIn(w http.ResponseWriter, r *http.Request, id string, leaseCtx context.Context) {
	guestPaths := r.URL.Query()["path"]
	if len(guestPaths) != 1 || !path.IsAbs(guestPaths[0]) {
		http.Error(w, "exactly one absolute guest path is required", http.StatusBadRequest)
		return
	}
	if r.ContentLength > s.maxUpload {
		http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := fenced(r, leaseCtx)
	defer cancel()
	tmp, err := os.CreateTemp("", "sandboxd-worker-upload-*")
	if err != nil {
		http.Error(w, "cannot stage upload", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, http.MaxBytesReader(w, r.Body, s.maxUpload))
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "cannot stage upload", http.StatusBadRequest)
		}
		return
	}
	if err := s.driver.CopyIn(ctx, id, tmp.Name(), guestPaths[0]); err != nil {
		if leaseCtx.Err() != nil {
			http.Error(w, staleMessage, http.StatusConflict)
			return
		}
		driverFailed(w, "copy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) run(w http.ResponseWriter, r *http.Request, id string, leaseCtx context.Context) {
	var request runRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.Args) == 0 {
		http.Error(w, "args are required", http.StatusBadRequest)
		return
	}
	ctx, cancel := fenced(r, leaseCtx)
	defer cancel()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	frames := &frameWriter{w: w, rc: http.NewResponseController(w)}
	frames.flush()
	command := vm.Command{
		Args: request.Args, Dir: request.Dir, Env: request.Env, User: request.User,
		OnStart: func(pid int) { _ = frames.frame(frameStarted, []byte(strconv.Itoa(pid))) },
	}
	code, err := s.driver.Run(ctx, id, command, frames.stream(frameStdout), frames.stream(frameStderr))
	// A run fenced off by re-enrollment must never report an exit status.
	switch {
	case leaseCtx.Err() != nil:
		frames.final(frameFailure, staleMessage)
	case err != nil:
		frames.final(frameFailure, "run failed")
	default:
		frames.final(frameExit, strconv.Itoa(code))
	}
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request, id string, _ context.Context) {
	if s.meter == nil {
		http.Error(w, ErrNoMetrics.Error(), http.StatusNotImplemented)
		return
	}
	usage, err := s.meter.Usage(r.Context(), id)
	if err != nil {
		driverFailed(w, "usage")
		return
	}
	writeJSON(w, http.StatusOK, usageJSON(usage))
}

// frameWriter serializes run frames ([kind][uint32 big-endian length][data])
// onto the response, flushing each one. Once the terminal frame is written or
// a write fails, every later write fails, so a driver that outlives the
// handler can never touch the response.
type frameWriter struct {
	mu     sync.Mutex
	w      io.Writer
	rc     *http.ResponseController
	err    error
	header [5]byte
}

var errStreamClosed = errors.New("run stream closed")

func (f *frameWriter) frame(kind byte, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frameLocked(kind, data)
}

func (f *frameWriter) frameLocked(kind byte, data []byte) error {
	if f.err != nil {
		return f.err
	}
	f.header[0] = kind
	binary.BigEndian.PutUint32(f.header[1:], uint32(len(data)))
	if _, err := f.w.Write(f.header[:]); err != nil {
		f.err = err
		return err
	}
	if _, err := f.w.Write(data); err != nil {
		f.err = err
		return err
	}
	if err := f.rc.Flush(); err != nil {
		f.err = err
		return err
	}
	return nil
}

func (f *frameWriter) flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.rc.Flush(); err != nil {
		f.err = err
	}
}

func (f *frameWriter) final(kind byte, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.frameLocked(kind, []byte(message))
	f.err = errStreamClosed
}

func (f *frameWriter) stream(kind byte) io.Writer { return streamWriter{f, kind} }

type streamWriter struct {
	f    *frameWriter
	kind byte
}

func (s streamWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), maxFrameData)]
		if err := s.f.frame(s.kind, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(dst)
	if err == nil && decoder.Decode(&struct{}{}) != io.EOF {
		err = errors.New("trailing data after JSON body")
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "cannot encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// driverFailed reports a driver error without leaking its details, which can
// include host paths and tool output.
func driverFailed(w http.ResponseWriter, operation string) {
	http.Error(w, fmt.Sprintf("worker driver %s failed", operation), http.StatusBadGateway)
}
