package envd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gitmoot/sandboxd/internal/vm"
)

type allowedSandbox struct{}

func (allowedSandbox) Authorize(id, token string) bool {
	return id == "sandboxd-a1" && token == "job-capability"
}
func (allowedSandbox) Abort(context.Context, string, string) error { return nil }

type guestFixture struct{ uploaded string }

func (*guestFixture) Create(context.Context, vm.Spec) (vm.Instance, error) { panic("unused") }
func (*guestFixture) List(context.Context) ([]vm.Instance, error)          { panic("unused") }
func (*guestFixture) Destroy(context.Context, string) error                { panic("unused") }
func (g *guestFixture) CopyIn(_ context.Context, id, src, dst string) error {
	if id != "sandboxd-a1" || dst != "/home/user/input" {
		panic("incorrect guest destination")
	}
	data, err := os.ReadFile(src)
	g.uploaded = string(data)
	return err
}
func (*guestFixture) Run(_ context.Context, id string, command vm.Command, stdout, stderr io.Writer) (int, error) {
	if id != "sandboxd-a1" || command.Args[0] != "/bin/echo" || command.User != "user" {
		panic("incorrect guest process")
	}
	command.OnStart(123)
	_, _ = stdout.Write([]byte("ready\n"))
	_, _ = stderr.Write([]byte("warning\n"))
	return 0, nil
}

func TestGuestStartStreamsAuthenticatedConnectEvents(t *testing.T) {
	guest := &guestFixture{}
	h := &Handler{Driver: guest, Authorizer: allowedSandbox{}, Domain: "private.test", GatewayHost: "mac.private.test"}
	body := framed(0, []byte(`{"process":{"cmd":"/bin/echo","args":["ready"],"cwd":"/home/user"},"stdin":false}`))
	r := httptest.NewRequest(http.MethodPost, "http://mac.private.test/process.Process/Start", bytes.NewReader(body))
	r.Header.Set("X-Access-Token", "job-capability")
	r.Header.Set("E2b-Sandbox-Id", "sandboxd-a1")
	r.Header.Set("E2b-Sandbox-Port", "49983")
	r.Header.Set("Content-Type", connectMediaType)
	r.Header.Set("connect-protocol-version", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != connectMediaType {
		t.Fatalf("Connect response: status=%d type=%q body=%q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	reader := bytes.NewReader(w.Body.Bytes())
	var events []map[string]json.RawMessage
	for {
		flag, payload := nextFrame(t, reader)
		if flag == 2 {
			if string(payload) != "{}" || reader.Len() != 0 {
				t.Fatalf("invalid terminal frame: %q", payload)
			}
			break
		}
		if flag != 0 {
			t.Fatalf("unexpected frame flag %d", flag)
		}
		var wrapper struct {
			Event map[string]json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal(payload, &wrapper); err != nil {
			t.Fatal(err)
		}
		events = append(events, wrapper.Event)
	}
	if len(events) != 4 || events[0]["start"] == nil || events[1]["data"] == nil || events[2]["data"] == nil || events[3]["end"] == nil {
		t.Fatalf("wrong start/data/end sequence: %v", events)
	}
	var first struct {
		Stdout []byte `json:"stdout"`
	}
	var second struct {
		Stderr []byte `json:"stderr"`
	}
	var end struct {
		ExitCode int  `json:"exitCode"`
		Exited   bool `json:"exited"`
	}
	if err := json.Unmarshal(events[1]["data"], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(events[2]["data"], &second); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(events[3]["end"], &end); err != nil {
		t.Fatal(err)
	}
	if string(first.Stdout) != "ready\n" || string(second.Stderr) != "warning\n" || !end.Exited || end.ExitCode != 0 {
		t.Fatalf("stream lost process output or terminal result: stdout=%q stderr=%q end=%+v", first.Stdout, second.Stderr, end)
	}
}

func TestGuestUploadRequiresCapabilityAndConfinedPath(t *testing.T) {
	guest := &guestFixture{}
	h := &Handler{Driver: guest, Authorizer: allowedSandbox{}, GatewayHost: "mac.private.test"}
	request := func(target, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader("source bytes"))
		r.Header.Set("E2b-Sandbox-Id", "sandboxd-a1")
		r.Header.Set("E2b-Sandbox-Port", "49983")
		r.Header.Set("X-Access-Token", token)
		r.Header.Set("Content-Type", "application/octet-stream")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if got := request("http://mac.private.test/files?username=user&path=/home/user/input", "wrong").Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong token accepted: %d", got)
	}
	if got := request("http://mac.private.test/files?username=user&path=/home/user/../etc/passwd", "job-capability").Code; got != http.StatusBadRequest {
		t.Fatalf("traversal accepted: %d", got)
	}
	if got := request("http://mac.private.test/files?username=user&path=/home/user/input", "job-capability").Code; got != http.StatusOK || guest.uploaded != "source bytes" {
		t.Fatalf("valid upload failed: status=%d data=%q", got, guest.uploaded)
	}
	h.MaxUploadBytes = 4
	if got := request("http://mac.private.test/files?username=user&path=/home/user/input", "job-capability").Code; got != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload accepted: %d", got)
	}
}

func TestGuestStartRejectsTruncatedFrame(t *testing.T) {
	guest := &guestFixture{}
	h := &Handler{Driver: guest, Authorizer: allowedSandbox{}, GatewayHost: "mac.private.test"}
	body := framed(0, []byte(`{}`))
	binary.BigEndian.PutUint32(body[1:5], uint32(len(body)))
	r := httptest.NewRequest(http.MethodPost, "http://mac.private.test/process.Process/Start", bytes.NewReader(body))
	r.Header.Set("X-Access-Token", "job-capability")
	r.Header.Set("E2b-Sandbox-Id", "sandboxd-a1")
	r.Header.Set("E2b-Sandbox-Port", "49983")
	r.Header.Set("Content-Type", connectMediaType)
	r.Header.Set("connect-protocol-version", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("truncated Connect frame reached guest: %d", w.Code)
	}
}

func framed(flag byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}
func nextFrame(t *testing.T, r *bytes.Reader) (byte, []byte) {
	t.Helper()
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatal(err)
	}
	return header[0], payload
}

type canceledGuestFixture struct {
	guestFixture
	started chan struct{}
}

func (g *canceledGuestFixture) Run(ctx context.Context, _ string, command vm.Command, _, _ io.Writer) (int, error) {
	command.OnStart(123)
	close(g.started)
	<-ctx.Done()
	return 0, ctx.Err()
}

type abortRecorder struct{ calls chan string }

func (abortRecorder) Authorize(id, token string) bool {
	return allowedSandbox{}.Authorize(id, token)
}
func (a abortRecorder) Abort(_ context.Context, id, token string) error {
	a.calls <- id + ":" + token
	return nil
}

func TestCanceledGuestStreamRevokesBeforeReturning(t *testing.T) {
	guest := &canceledGuestFixture{started: make(chan struct{})}
	auth := abortRecorder{calls: make(chan string, 1)}
	h := &Handler{Driver: guest, Authorizer: auth, GatewayHost: "mac.private.test"}
	body := framed(0, []byte(`{"process":{"cmd":"/bin/sleep","args":["60"],"cwd":"/home/user"}}`))
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "http://mac.private.test/process.Process/Start", bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("X-Access-Token", "job-capability")
	r.Header.Set("E2b-Sandbox-Id", "sandboxd-a1")
	r.Header.Set("E2b-Sandbox-Port", "49983")
	r.Header.Set("Content-Type", connectMediaType)
	r.Header.Set("connect-protocol-version", "1")
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), r)
		close(done)
	}()
	<-guest.started
	cancel()
	<-done
	select {
	case got := <-auth.calls:
		if got != "sandboxd-a1:job-capability" {
			t.Fatalf("wrong VM capability revoked: %q", got)
		}
	default:
		t.Fatal("canceled stream did not revoke its VM")
	}
}

type noisyGuestFixture struct{ guestFixture }

func (*noisyGuestFixture) Run(_ context.Context, _ string, command vm.Command, stdout, stderr io.Writer) (int, error) {
	command.OnStart(123)
	if _, err := stdout.Write([]byte("good")); err != nil {
		return 0, err
	}
	// A guest exit status can mask an asynchronous stdout copy error in os/exec.
	_, _ = stderr.Write([]byte("overflow"))
	return 0, nil
}

func TestGuestOutputBudgetAbortsVM(t *testing.T) {
	auth := abortRecorder{calls: make(chan string, 1)}
	h := &Handler{Driver: &noisyGuestFixture{}, Authorizer: auth, GatewayHost: "mac.private.test", MaxOutputBytes: 4}
	body := framed(0, []byte(`{"process":{"cmd":"/bin/echo","cwd":"/home/user"}}`))
	r := httptest.NewRequest(http.MethodPost, "http://mac.private.test/process.Process/Start", bytes.NewReader(body))
	r.Header.Set("X-Access-Token", "job-capability")
	r.Header.Set("E2b-Sandbox-Id", "sandboxd-a1")
	r.Header.Set("E2b-Sandbox-Port", "49983")
	r.Header.Set("Content-Type", connectMediaType)
	r.Header.Set("connect-protocol-version", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("unexpected process response: %d", w.Code)
	}
	select {
	case got := <-auth.calls:
		if got != "sandboxd-a1:job-capability" {
			t.Fatalf("wrong VM aborted after output overflow: %s", got)
		}
	default:
		t.Fatal("overflow did not abort the VM")
	}
	frames := bytes.NewReader(w.Body.Bytes())
	_, _ = nextFrame(t, frames) // start
	_, data := nextFrame(t, frames)
	var event struct {
		Event struct {
			Data map[string][]byte `json:"data"`
		} `json:"event"`
	}
	if err := json.Unmarshal(data, &event); err != nil || string(event.Event.Data["stdout"]) != "good" {
		t.Fatalf("stream lost the accepted output: %s, %v", data, err)
	}
	flag, terminal := nextFrame(t, frames)
	if flag != 2 || !bytes.Contains(terminal, []byte("unavailable")) || frames.Len() != 0 {
		t.Fatalf("overflow returned a successful process stream: %s", terminal)
	}
}
