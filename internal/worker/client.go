package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// Client is the gateway's view of a remote worker. It implements Member.
//
// Every call other than Enroll is refused locally until Enroll succeeds, and
// is then made under the lease that enrollment presented. A worker that has
// since accepted a newer lease answers 409, which Client reports as an error
// wrapping ErrStaleLease.
type Client struct {
	id     string
	base   string
	auth   string
	client *http.Client

	mu    sync.Mutex
	lease int64 // 0 until Enroll succeeds
}

var _ Member = (*Client)(nil)

var errNotEnrolled = errors.New("worker is not enrolled")

// NewClient returns the gateway's view of the remote worker enrolled as id.
// baseURL must be https://..., or http:// only for a loopback IP host. A nil
// httpClient selects defaultHTTPClient. Callers bound every call with its
// context.
func NewClient(id, baseURL, key string, httpClient *http.Client) (*Client, error) {
	if !workerIDPattern.MatchString(id) {
		return nil, fmt.Errorf("worker id %q must match %s", id, workerIDPattern)
	}
	if err := validKey(key); err != nil {
		return nil, err
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("worker %s: invalid URL: %w", id, err)
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.Opaque != "" {
		return nil, fmt.Errorf("worker %s: URL must be scheme://host[:port][/path] without credentials, query, or fragment", id)
	}
	switch base.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(base.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("worker %s: plaintext http is only allowed for a loopback IP host", id)
		}
	default:
		return nil, fmt.Errorf("worker %s: URL scheme must be https", id)
	}
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Client{
		id:     id,
		base:   strings.TrimSuffix(base.String(), "/") + strings.TrimSuffix(apiPrefix, "/"),
		auth:   "Bearer " + key,
		client: httpClient,
	}, nil
}

// Transport bounds for the default client. They stop a black-holed connection
// (a tailnet partition mid-request) from holding a call forever even if its
// context has no deadline. The response-header bound is a backstop above the
// slowest worker answer, a Create that boots a VM or a large CopyIn; gateway
// contexts set the tighter per-call deadlines. Streamed Run output is not
// bounded: a job's process may run for its whole TTL.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 5 * time.Minute
)

// defaultHTTPClient does not follow redirects and bounds dialing, the TLS
// handshake and the wait for response headers.
func defaultHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = tlsHandshakeTimeout
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	return &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Enroll presents lease and returns the worker's declaration. It refuses a
// declaration for a different worker ID (swapped credentials or URLs) or an
// invalid one. On any failure the client is left unenrolled.
func (c *Client) Enroll(ctx context.Context, lease int64) (Declaration, error) {
	c.setLease(0)
	if lease < 1 {
		return Declaration{}, fmt.Errorf("worker %s: lease must be >= 1", c.id)
	}
	body, err := json.Marshal(enrollRequest{Lease: lease})
	if err != nil {
		return Declaration{}, err
	}
	resp, err := c.send(ctx, http.MethodPost, "/enroll", nil, 0, bytes.NewReader(body), int64(len(body)), "application/json")
	if err != nil {
		return Declaration{}, err
	}
	defer resp.Body.Close()
	if err := c.expect(resp, http.StatusOK); err != nil {
		return Declaration{}, err
	}
	var decl Declaration
	if err := decodeResponse(resp, &decl); err != nil {
		return Declaration{}, fmt.Errorf("worker %s: enroll: %w", c.id, err)
	}
	if decl.ID != c.id {
		return Declaration{}, fmt.Errorf("worker %s: enrolled worker declares id %q", c.id, decl.ID)
	}
	if err := decl.Validate(); err != nil {
		return Declaration{}, fmt.Errorf("worker %s: invalid declaration: %w", c.id, err)
	}
	c.setLease(lease)
	return decl, nil
}

// Create creates a VM that the worker destroys at its own max TTL.
func (c *Client) Create(ctx context.Context, spec vm.Spec) (vm.Instance, error) {
	return c.CreateUntil(ctx, spec, time.Time{})
}

// CreateUntil creates a VM that the worker destroys on its own at ends,
// capped by the worker's max TTL.
func (c *Client) CreateUntil(ctx context.Context, spec vm.Spec, ends time.Time) (vm.Instance, error) {
	body, err := json.Marshal(createRequest{ID: spec.ID, Image: spec.Image, Network: spec.Network, CPUs: spec.CPUs,
		MemoryMiB: spec.MemoryMiB, Ends: ends.UTC()})
	if err != nil {
		return vm.Instance{}, err
	}
	resp, err := c.leased(ctx, http.MethodPost, "/vms", nil, bytes.NewReader(body), int64(len(body)), "application/json")
	if err != nil {
		return vm.Instance{}, err
	}
	defer resp.Body.Close()
	if err := c.expect(resp, http.StatusCreated); err != nil {
		return vm.Instance{}, err
	}
	var instance instanceJSON
	if err := decodeResponse(resp, &instance); err != nil {
		return vm.Instance{}, fmt.Errorf("worker %s: create: %w", c.id, err)
	}
	if instance.ID != spec.ID {
		return vm.Instance{}, fmt.Errorf("worker %s: create %s returned VM %q", c.id, spec.ID, instance.ID)
	}
	return vm.Instance(instance), nil
}

// Expire moves the worker-side end time of VM id.
func (c *Client) Expire(ctx context.Context, id string, ends time.Time) error {
	if err := c.checkVM(id); err != nil {
		return err
	}
	if ends.IsZero() {
		return fmt.Errorf("worker %s: expire %s: end time is required", c.id, id)
	}
	body, err := json.Marshal(expiryRequest{Ends: ends.UTC()})
	if err != nil {
		return err
	}
	resp, err := c.leased(ctx, http.MethodPut, "/vms/"+id+"/expiry", nil, bytes.NewReader(body), int64(len(body)), "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return c.expect(resp, http.StatusNoContent)
}

func (c *Client) List(ctx context.Context) ([]vm.Instance, error) {
	resp, err := c.leased(ctx, http.MethodGet, "/vms", nil, nil, 0, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := c.expect(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var listed []instanceJSON
	if err := decodeResponse(resp, &listed); err != nil {
		return nil, fmt.Errorf("worker %s: list: %w", c.id, err)
	}
	if listed == nil {
		return nil, fmt.Errorf("worker %s: list: missing inventory", c.id)
	}
	instances := make([]vm.Instance, len(listed))
	for i, instance := range listed {
		instances[i] = vm.Instance(instance)
	}
	return instances, nil
}

// CopyIn streams hostPath, a regular file, to the worker without buffering it.
func (c *Client) CopyIn(ctx context.Context, id, hostPath, guestPath string) error {
	if err := c.checkVM(id); err != nil {
		return err
	}
	file, err := os.Open(hostPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("worker %s: copy source %s is not a regular file", c.id, hostPath)
	}
	if info.Size() > maxUpload {
		return fmt.Errorf("worker %s: copy source %s exceeds %d bytes", c.id, hostPath, maxUpload)
	}
	var body io.Reader = file
	if info.Size() == 0 {
		body = http.NoBody
	}
	resp, err := c.leased(ctx, http.MethodPut, "/vms/"+id+"/files", url.Values{"path": {guestPath}}, body, info.Size(), "application/octet-stream")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return c.expect(resp, http.StatusNoContent)
}

// Run streams the command's output into stdout and stderr. It returns the
// exit code only when the worker reports one; a failure frame, a stream that
// ends without a terminal frame, or a local writer error is an error.
func (c *Client) Run(ctx context.Context, id string, cmd vm.Command, stdout, stderr io.Writer) (int, error) {
	if err := c.checkVM(id); err != nil {
		return 0, err
	}
	body, err := json.Marshal(runRequest{Args: cmd.Args, Dir: cmd.Dir, Env: cmd.Env, User: cmd.User})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resp, err := c.leased(ctx, http.MethodPost, "/vms/"+id+"/run", nil, bytes.NewReader(body), int64(len(body)), "application/json")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if err := c.expect(resp, http.StatusOK); err != nil {
		return 0, err
	}
	reader := bufio.NewReader(resp.Body)
	started := false
	var header [5]byte
	buf := make([]byte, maxFrameData)
	for {
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return 0, fmt.Errorf("worker %s: run %s: stream ended without exit status: %w: %w", c.id, id, ErrUnavailable, err)
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size > maxFrameData {
			return 0, fmt.Errorf("worker %s: run %s: oversized frame", c.id, id)
		}
		data := buf[:size]
		if _, err := io.ReadFull(reader, data); err != nil {
			return 0, fmt.Errorf("worker %s: run %s: stream ended without exit status: %w: %w", c.id, id, ErrUnavailable, err)
		}
		switch header[0] {
		case frameStarted:
			pid, err := strconv.Atoi(string(data))
			if started || err != nil {
				return 0, fmt.Errorf("worker %s: run %s: invalid start frame", c.id, id)
			}
			started = true
			if cmd.OnStart != nil {
				cmd.OnStart(pid)
			}
		case frameStdout, frameStderr:
			out := stdout
			if header[0] == frameStderr {
				out = stderr
			}
			if _, err := out.Write(data); err != nil {
				cancel() // abort the remote run
				return 0, err
			}
		case frameExit:
			code, err := strconv.Atoi(string(data))
			if err != nil {
				return 0, fmt.Errorf("worker %s: run %s: invalid exit frame", c.id, id)
			}
			if err := endOfStream(reader); err != nil {
				return 0, fmt.Errorf("worker %s: run %s: %w", c.id, id, err)
			}
			return code, nil
		case frameFailure:
			message := string(data)
			if message == staleMessage {
				return 0, fmt.Errorf("worker %s: run %s: %w", c.id, id, ErrStaleLease)
			}
			return 0, fmt.Errorf("worker %s: run %s: %q", c.id, id, message)
		default:
			return 0, fmt.Errorf("worker %s: run %s: unknown frame kind %q", c.id, id, header[0])
		}
	}
}

func endOfStream(reader *bufio.Reader) error {
	if _, err := reader.ReadByte(); err != io.EOF {
		if err == nil {
			return errors.New("data after the terminal frame")
		}
		return err
	}
	return nil
}

func (c *Client) Destroy(ctx context.Context, id string) error {
	if err := c.checkVM(id); err != nil {
		return err
	}
	resp, err := c.leased(ctx, http.MethodDelete, "/vms/"+id, nil, nil, 0, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return c.expect(resp, http.StatusNoContent)
}

// Usage returns measured VM usage, or ErrNoMetrics when the worker's driver
// cannot measure it.
func (c *Client) Usage(ctx context.Context, id string) (vm.Usage, error) {
	if err := c.checkVM(id); err != nil {
		return vm.Usage{}, err
	}
	resp, err := c.leased(ctx, http.MethodGet, "/vms/"+id+"/usage", nil, nil, 0, "")
	if err != nil {
		return vm.Usage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotImplemented {
		return vm.Usage{}, fmt.Errorf("worker %s: %w", c.id, ErrNoMetrics)
	}
	if err := c.expect(resp, http.StatusOK); err != nil {
		return vm.Usage{}, err
	}
	var usage usageJSON
	if err := decodeResponse(resp, &usage); err != nil {
		return vm.Usage{}, fmt.Errorf("worker %s: usage: %w", c.id, err)
	}
	return vm.Usage(usage), nil
}

func (c *Client) setLease(lease int64) {
	c.mu.Lock()
	c.lease = lease
	c.mu.Unlock()
}

func (c *Client) checkVM(id string) error {
	if !vmIDPattern.MatchString(id) {
		return fmt.Errorf("worker %s: invalid VM id %q", c.id, id)
	}
	return nil
}

// leased sends a request under the current lease; before a successful Enroll
// it fails without network I/O.
func (c *Client) leased(ctx context.Context, method, route string, query url.Values, body io.Reader, length int64, contentType string) (*http.Response, error) {
	c.mu.Lock()
	lease := c.lease
	c.mu.Unlock()
	if lease == 0 {
		return nil, fmt.Errorf("worker %s: %w: %w", c.id, ErrUnavailable, errNotEnrolled)
	}
	return c.send(ctx, method, route, query, lease, body, length, contentType)
}

func (c *Client) send(ctx context.Context, method, route string, query url.Values, lease int64, body io.Reader, length int64, contentType string) (*http.Response, error) {
	target := c.base + route
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = length
	}
	req.Header.Set("Authorization", c.auth)
	if lease != 0 {
		req.Header.Set(leaseHeader, strconv.FormatInt(lease, 10))
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("worker %s: %s %s: %w: %w", c.id, method, route, ErrUnavailable, err)
	}
	return resp, nil
}

// expect maps any status but want to an error. A 409 is a stale lease, or,
// when the worker says it is not enrolled under this lease (it restarted),
// ErrUnavailable. A failure reported by the worker's driver is a plain error;
// any other server error came from the transport in front of the worker and
// is ErrUnavailable.
func (c *Client) expect(resp *http.Response, want int) error {
	if resp.StatusCode == want {
		return nil
	}
	message, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	route := resp.Request.URL.Path
	if resp.StatusCode == http.StatusConflict {
		if resp.Header.Get(leaseStateHeader) == "unenrolled" {
			return fmt.Errorf("worker %s: %s %s: %w: %w", c.id, resp.Request.Method, route, ErrUnavailable, errNotEnrolled)
		}
		current, _ := strconv.ParseInt(resp.Header.Get(currentLeaseHeader), 10, 64)
		return fmt.Errorf("worker %s: %s %s: %w", c.id, resp.Request.Method, route, &StaleLeaseError{Current: current})
	}
	err := fmt.Errorf("worker %s: %s %s: status %d: %q", c.id, resp.Request.Method, route,
		resp.StatusCode, strings.TrimSpace(string(message)))
	if resp.StatusCode >= 500 && resp.Header.Get(driverErrorHeader) == "" {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return err
}

func decodeResponse(resp *http.Response, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing data after JSON response")
	}
	return nil
}
