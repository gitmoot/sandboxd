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
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

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
//
// The server also enforces every VM's end time on its own (see Reap), so a
// guest never outlives its TTL because the gateway is unreachable.
type Server struct {
	driver    vm.Driver
	meter     vm.ResourceMeter
	decl      Declaration
	keyHash   [sha256.Size]byte
	maxUpload int64
	maxTTL    time.Duration
	now       func() time.Time

	mu          sync.Mutex
	lease       int64 // highest accepted lease; 0 until the first enrollment
	leaseCtx    context.Context
	leaseCancel context.CancelFunc
	// ends is each known VM's end time. A VM first seen without one (after a
	// worker restart) gets maxTTL from that moment.
	ends map[string]time.Time
	// endsGen records, per end time, the value of gen when it was last set.
	// Reap prunes only end times older than its inventory snapshot, so an end
	// time set while the snapshot was being taken is never lost.
	endsGen map[string]uint64
	gen     uint64
	// creating holds VMs whose Create is in flight; they may not be listed yet.
	creating map[string]bool
}

// NewServer exposes driver, declared as decl, to a gateway holding key, the
// per-worker enrollment secret (>= 16 bytes of visible ASCII). maxTTL caps
// every VM's lifetime on this worker, whatever end time the gateway sends.
func NewServer(driver vm.Driver, decl Declaration, key string, maxTTL time.Duration) (*Server, error) {
	if driver == nil {
		return nil, errors.New("worker driver is required")
	}
	if err := decl.Validate(); err != nil {
		return nil, err
	}
	if err := validKey(key); err != nil {
		return nil, err
	}
	if maxTTL < time.Second {
		return nil, errors.New("worker max TTL must be at least one second")
	}
	s := &Server{driver: driver, decl: decl.clone(), keyHash: sha256.Sum256([]byte(key)), maxUpload: maxUpload,
		maxTTL: maxTTL, now: time.Now, ends: make(map[string]time.Time), endsGen: make(map[string]uint64),
		creating: make(map[string]bool)}
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
	case len(parts) < 2 || len(parts) > 4 || parts[0] != "vms" || !vmIDPattern.MatchString(parts[1]):
		http.NotFound(w, r)
		return
	}
	id := parts[1]
	var method string
	var handle func(http.ResponseWriter, *http.Request, string, context.Context)
	switch {
	case len(parts) == 2:
		method, handle = http.MethodDelete, s.destroy
	case len(parts) == 4:
		port, err := strconv.Atoi(parts[3])
		if parts[2] != "ports" || err != nil || !vm.ValidPort(port) || strconv.Itoa(port) != parts[3] {
			http.NotFound(w, r)
			return
		}
		method = http.MethodPost
		handle = func(w http.ResponseWriter, r *http.Request, id string, leaseCtx context.Context) {
			s.port(w, r, id, port, leaseCtx)
		}
	case parts[2] == "files":
		method, handle = http.MethodPut, s.copyIn
	case parts[2] == "run":
		method, handle = http.MethodPost, s.run
	case parts[2] == "console":
		method, handle = http.MethodGet, s.console
	case parts[2] == "usage":
		method, handle = http.MethodGet, s.usage
	case parts[2] == "expiry":
		method, handle = http.MethodPut, s.expire
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
		current := s.lease
		s.mu.Unlock()
		staleLease(w, current)
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
// handler that lease's context, which is cancelled on re-enrollment. A lower
// lease is stale (a newer gateway took over); a higher one, or any lease
// before the first enrollment, is unenrolled (this worker restarted), and the
// gateway re-enrolls.
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
	switch {
	case lease < current:
		staleLease(w, current)
	case lease > current:
		w.Header().Set(leaseStateHeader, "unenrolled")
		http.Error(w, "worker is not enrolled under this lease", http.StatusConflict)
	default:
		handle(w, r, leaseCtx)
	}
}

func staleLease(w http.ResponseWriter, current int64) {
	w.Header().Set(leaseStateHeader, "stale")
	w.Header().Set(currentLeaseHeader, strconv.FormatInt(current, 10))
	http.Error(w, staleMessage, http.StatusConflict)
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
		driverFailed(w, "list", err)
		return
	}
	out := make([]instanceJSON, 0, len(instances))
	for _, instance := range instances {
		out = append(out, instanceJSON(instance))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) create(w http.ResponseWriter, r *http.Request, leaseCtx context.Context) {
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
		// Record the end time before the VM can exist, so the reaper never
		// sees it without one.
		s.mu.Lock()
		s.setEnd(request.ID, s.capEnd(request.Ends))
		s.creating[request.ID] = true
		s.mu.Unlock()
		instance, err := s.driver.Create(r.Context(), vm.Spec{ID: request.ID, Image: request.Image, Network: request.Network,
			CPUs: request.CPUs, MemoryMiB: request.MemoryMiB, Envd: request.Envd})
		s.mu.Lock()
		delete(s.creating, request.ID)
		// Re-stamp the end time as the VM becomes visible: a Reap whose
		// inventory was taken while this Create ran saw neither the VM nor the
		// creating mark, and must not prune the end time as stale.
		if _, known := s.ends[request.ID]; known {
			s.gen++
			s.endsGen[request.ID] = s.gen
		}
		s.mu.Unlock()
		// A newer gateway enrolled while this Create ran: the caller no longer
		// owns this worker and must not admit the VM. The new owner's
		// reconciliation finds it without a ledger row and destroys it.
		if leaseCtx.Err() != nil {
			s.mu.Lock()
			current := s.lease
			s.mu.Unlock()
			staleLease(w, current)
			return
		}
		if err != nil {
			driverFailed(w, "create", err)
			return
		}
		writeJSON(w, http.StatusCreated, instanceJSON(instance))
	}
}

// capEnd bounds a requested end time by this worker's max TTL from now; a
// zero end time means the max TTL. Callers hold s.mu.
func (s *Server) capEnd(ends time.Time) time.Time {
	limit := s.now().Add(s.maxTTL)
	if ends.IsZero() || ends.After(limit) {
		return limit
	}
	return ends
}

func (s *Server) expire(w http.ResponseWriter, r *http.Request, id string, _ context.Context) {
	var request expiryRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Ends.IsZero() {
		http.Error(w, "ends is required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.setEnd(id, s.capEnd(request.Ends))
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// setEnd records a VM's end time. Callers hold s.mu.
func (s *Server) setEnd(id string, ends time.Time) {
	s.gen++
	s.ends[id] = ends
	s.endsGen[id] = s.gen
}

// dropEnd forgets a VM's end time. Callers hold s.mu.
func (s *Server) dropEnd(id string) {
	delete(s.ends, id)
	delete(s.endsGen, id)
}

// Reap destroys every VM whose end time has passed, using one complete
// inventory. A VM seen for the first time without an end time (it predates a
// worker restart) gets the max TTL from now. End times of VMs absent from the
// inventory are pruned, except those set after the inventory was requested:
// their VM may have been created after the snapshot. A failed destroy is
// retried on the next pass.
func (s *Server) Reap(ctx context.Context) error {
	s.mu.Lock()
	snapshot := s.gen
	s.mu.Unlock()
	instances, err := s.driver.List(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	now := s.now()
	present := make(map[string]bool, len(instances))
	var expired []string
	for _, instance := range instances {
		present[instance.ID] = true
		ends, known := s.ends[instance.ID]
		if !known {
			ends = now.Add(s.maxTTL)
			s.setEnd(instance.ID, ends)
		}
		if !now.Before(ends) && !s.creating[instance.ID] {
			expired = append(expired, instance.ID)
		}
	}
	for id := range s.ends {
		if !present[id] && !s.creating[id] && s.endsGen[id] <= snapshot {
			s.dropEnd(id)
		}
	}
	s.mu.Unlock()
	var errs []error
	for _, id := range expired {
		if err := s.driver.Destroy(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("destroy expired VM %s: %w", id, err))
			continue
		}
		log.Printf("worker %s: destroyed VM %s at the end of its lifetime", s.decl.ID, id)
		s.mu.Lock()
		s.dropEnd(id)
		s.mu.Unlock()
	}
	return errors.Join(errs...)
}

// ReapEvery runs Reap every interval until ctx ends, logging failures.
func (s *Server) ReapEvery(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			passCtx, cancel := context.WithTimeout(ctx, time.Minute)
			if err := s.Reap(passCtx); err != nil && ctx.Err() == nil {
				log.Printf("worker %s: expiry pass: %v", s.decl.ID, err)
			}
			cancel()
		}
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
		driverFailed(w, "destroy", err)
		return
	}
	s.mu.Lock()
	s.dropEnd(id)
	s.mu.Unlock()
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
			s.mu.Lock()
			current := s.lease
			s.mu.Unlock()
			staleLease(w, current)
			return
		}
		driverFailed(w, "copy", err)
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

// port upgrades the request to a raw byte stream to a TCP port of VM id,
// opened by the driver over its host-to-guest channel. The stream ends when
// either side closes it, or when a newer lease supersedes the one it was
// opened under.
func (s *Server) port(w http.ResponseWriter, r *http.Request, id string, port int, leaseCtx context.Context) {
	dialer, ok := s.driver.(vm.PortDialer)
	if !ok {
		http.Error(w, vm.ErrNoEnvd.Error(), http.StatusNotImplemented)
		return
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), portUpgrade) {
		http.Error(w, "a port stream must upgrade to "+portUpgrade, http.StatusBadRequest)
		return
	}
	ctx, cancel := fenced(r, leaseCtx)
	defer cancel()
	guest, err := dialer.DialPort(ctx, id, port)
	if err != nil {
		driverFailed(w, "port", err)
		return
	}
	defer guest.Close()
	conn, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "port streams need HTTP/1.1", http.StatusHTTPVersionNotSupported)
		return
	}
	defer conn.Close()
	// The server's header and body deadlines must not end a long stream.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+portUpgrade+"\r\n\r\n"); err != nil {
		return
	}
	stop := context.AfterFunc(leaseCtx, func() { _ = conn.Close(); _ = guest.Close() })
	defer stop()
	Bridge(conn, buffered.Reader, guest)
}

// Bridge copies bytes between a client connection (read through in, which
// may hold bytes already buffered from it) and an upstream stream until
// either direction ends, then closes both and waits for the other direction.
func Bridge(client net.Conn, in io.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, in)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

// headerHasToken reports whether a comma-separated header lists token.
func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func (s *Server) usage(w http.ResponseWriter, r *http.Request, id string, _ context.Context) {
	if s.meter == nil {
		http.Error(w, ErrNoMetrics.Error(), http.StatusNotImplemented)
		return
	}
	usage, err := s.meter.Usage(r.Context(), id)
	if err != nil {
		driverFailed(w, "usage", err)
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
// include host paths and tool output, to the gateway; the worker's own log
// keeps them.
func driverFailed(w http.ResponseWriter, operation string, err error) {
	log.Printf("worker driver %s failed: %v", operation, err)
	w.Header().Set(driverErrorHeader, operation)
	http.Error(w, fmt.Sprintf("worker driver %s failed", operation), http.StatusBadGateway)
}
