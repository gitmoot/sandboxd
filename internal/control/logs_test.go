package control

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

type logsV2 struct {
	Logs []logEntry `json:"logs"`
}

type logsV1 struct {
	Logs       []v1LogLine `json:"logs"`
	LogEntries []logEntry  `json:"logEntries"`
}

func openLogsService(t *testing.T) (*Service, *fakeDriver, string) {
	t.Helper()
	driver := &fakeDriver{instances: map[string]vm.Instance{}, consoles: map[string][]vm.ConsoleLine{}}
	s := openAt(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, mixedConfig(e2bBase, 3))
	id := createE2B(t, s, map[string]any{"templateID": "base"}).ID
	return s, driver, id
}

var logsEpoch = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

// consoleAt returns console lines one second apart from logsEpoch.
func consoleAt(texts ...string) []vm.ConsoleLine {
	lines := make([]vm.ConsoleLine, len(texts))
	for i, text := range texts {
		lines[i] = vm.ConsoleLine{Time: logsEpoch.Add(time.Duration(i) * time.Second), Text: text}
	}
	return lines
}

func stamp(i int) string {
	return logsEpoch.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
}

func TestLogsServeTheGuestConsole(t *testing.T) {
	s, driver, id := openLogsService(t)
	driver.consoles[id] = consoleAt(
		"cgroups disabled via --no-cgroups; using no-op cgroup manager",
		`{"level":"debug","logger":"process","method":"POST /process.Process/Start","operation_id":"2","request":{"process":{"envs":{"TOKEN":"secret"}}},"timestamp":"1999-01-01T00:00:00Z","message":"Process start (server stream start)"}`,
		`{"level":"info","logger":"process","pid":18,"event_type":"process_start","exited":true,"message":"Process with pid 18 started"}`,
		`{"level":"error","logger":"envd","error":"path '/nope' does not exist","error_code":404,"message":"File read"}`,
		`{"level":"warn","message":"low disk","source":"spoofed"}`,
		`{"level":"fatal","message":7}`,
		"{not json",
	)
	got := request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs", nil)
	if got.Code != http.StatusOK || got.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("logs: %d %s", got.Code, got.Body.String())
	}
	want := []logEntry{
		{Timestamp: stamp(0), Level: "info", Message: "cgroups disabled via --no-cgroups; using no-op cgroup manager", Fields: map[string]string{}},
		// Nested values (envd's debug request bodies) are never served, and
		// the guest's own timestamp is not trusted.
		{Timestamp: stamp(1), Level: "debug", Message: "Process start (server stream start)",
			Fields: map[string]string{"source": "envd", "logger": "process", "method": "POST /process.Process/Start", "operation_id": "2"}},
		{Timestamp: stamp(2), Level: "info", Message: "Process with pid 18 started",
			Fields: map[string]string{"source": "envd", "logger": "process", "pid": "18", "event_type": "process_start", "exited": "true"}},
		{Timestamp: stamp(3), Level: "error", Message: "File read",
			Fields: map[string]string{"source": "envd", "logger": "envd", "error": "path '/nope' does not exist", "error_code": "404"}},
		{Timestamp: stamp(4), Level: "warn", Message: "low disk", Fields: map[string]string{"source": "envd"}},
		{Timestamp: stamp(5), Level: "error", Message: `{"level":"fatal","message":7}`, Fields: map[string]string{"source": "envd"}},
		{Timestamp: stamp(6), Level: "info", Message: "{not json", Fields: map[string]string{}},
	}
	if body := decodeBody[logsV2](t, got.Body); !reflect.DeepEqual(body.Logs, want) {
		t.Fatalf("logs =\n%+v\nwant\n%+v", body.Logs, want)
	}
	if strings.Contains(got.Body.String(), "secret") || strings.Contains(got.Body.String(), "1999") {
		t.Fatalf("logs serve nested or guest-stamped values: %s", got.Body.String())
	}

	messages := func(query string) []string {
		t.Helper()
		got := request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs"+query, nil)
		if got.Code != http.StatusOK {
			t.Fatalf("logs%s: %d %s", query, got.Code, got.Body.String())
		}
		var out []string
		for _, entry := range decodeBody[logsV2](t, got.Body).Logs {
			out = append(out, entry.Message)
		}
		return out
	}
	cursor := logsEpoch.Add(3 * time.Second).UnixMilli()
	for query, want := range map[string][]string{
		"?level=warn":                     {"File read", "low disk", `{"level":"fatal","message":7}`},
		"?level=error&search=File":        {"File read"},
		"?search=pid%2018":                {"Process with pid 18 started"},
		"?search=file":                    nil, // case-sensitive
		"?limit=2":                        {"cgroups disabled via --no-cgroups; using no-op cgroup manager", "Process start (server stream start)"},
		"?limit=0":                        nil,
		fmt.Sprintf("?cursor=%d", cursor): {"File read", "low disk", `{"level":"fatal","message":7}`, "{not json"},
		fmt.Sprintf("?cursor=%d&direction=backward&limit=2", cursor): {"File read", "Process with pid 18 started"},
		"?direction=backward&level=error":                            {`{"level":"fatal","message":7}`, "File read"},
		"?direction=forward&level=debug":                             messages(""),
	} {
		if got := messages(query); !reflect.DeepEqual(got, want) {
			t.Errorf("logs%s = %q, want %q", query, got, want)
		}
	}

	// The deprecated v1 route serves the same entries, and plain lines.
	got = request(t, s, http.MethodGet, fmt.Sprintf("/sandboxes/%s/logs?start=%d&limit=2", id, cursor), nil)
	v1 := decodeBody[logsV1](t, got.Body)
	if got.Code != http.StatusOK || !reflect.DeepEqual(v1.Logs, []v1LogLine{{Line: "File read", Timestamp: stamp(3)}, {Line: "low disk", Timestamp: stamp(4)}}) ||
		!reflect.DeepEqual(v1.LogEntries, want[3:5]) {
		t.Fatalf("v1 logs: %d %s", got.Code, got.Body.String())
	}
}

func TestLogsAreBounded(t *testing.T) {
	s, driver, id := openLogsService(t)
	texts := make([]string, 1500)
	for i := range texts {
		texts[i] = fmt.Sprintf("line %d", i)
	}
	driver.consoles[id] = consoleAt(texts...)
	got := request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs", nil)
	logs := decodeBody[logsV2](t, got.Body).Logs
	if got.Code != http.StatusOK || len(logs) != maxLogs || logs[0].Message != "line 0" || logs[maxLogs-1].Message != "line 999" {
		t.Fatalf("default page: %d, %d entries", got.Code, len(logs))
	}
	got = request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs?direction=backward", nil)
	if logs := decodeBody[logsV2](t, got.Body).Logs; len(logs) != maxLogs || logs[0].Message != "line 1499" {
		t.Fatalf("backward page: %d entries", len(logs))
	}
}

func TestLogsRefuseBadRequests(t *testing.T) {
	s, driver, id := openLogsService(t)
	driver.consoles[id] = nil
	for _, query := range []string{
		"?limit=1001", "?limit=-1", "?limit=x", "?limit=1&limit=2", "?cursor=-1", "?cursor=soon", "?direction=sideways",
		"?level=fatal", "?search=" + strings.Repeat("a", maxLogSearch+1), "?start=1", "?unknown=1",
	} {
		got := request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs"+query, nil)
		if failure := decodeBody[e2bError](t, got.Body); got.Code != http.StatusBadRequest || failure.Code != http.StatusBadRequest || failure.Message == "" {
			t.Errorf("logs%s: %d %s", query, got.Code, got.Body.String())
		}
	}
	// v1 knows only start and limit.
	if got := request(t, s, http.MethodGet, "/sandboxes/"+id+"/logs?cursor=1", nil); got.Code != http.StatusBadRequest {
		t.Errorf("v1 logs with a v2 parameter: %d", got.Code)
	}
	if got := request(t, s, http.MethodGet, "/v2/sandboxes/"+id+"/logs?limit=5", nil); got.Code != http.StatusOK || got.Body.String() != "{\"logs\":[]}\n" {
		t.Errorf("empty logs: %d %q", got.Code, got.Body.String())
	}
}

func TestLogsNeedALiveE2BSandboxWithAConsole(t *testing.T) {
	s, driver, id := openLogsService(t)
	path := "/v2/sandboxes/" + id + "/logs"
	strict := mustCreate(t, s, createBody("job-logs", 1)).ID
	unauthenticated := httptest.NewRecorder()
	s.Handler().ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, path, nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("logs without the API key: %d", unauthenticated.Code)
	}

	// The driver keeps no console for this guest.
	got := request(t, s, http.MethodGet, path, nil)
	if failure := decodeBody[e2bError](t, got.Body); got.Code != http.StatusNotImplemented || !strings.Contains(failure.Message, "keeps no console output") {
		t.Fatalf("logs without a console: %d %s", got.Code, got.Body.String())
	}

	if got := request(t, s, http.MethodGet, "/v2/sandboxes/"+strict+"/logs", nil); got.Code != http.StatusConflict {
		t.Fatalf("logs of a strict sandbox: %d %s", got.Code, got.Body.String())
	}

	driver.consoles[id] = consoleAt("x")
	if got := request(t, s, http.MethodDelete, "/sandboxes/"+id, nil); got.Code != http.StatusNoContent {
		t.Fatalf("kill: %d", got.Code)
	}
	for _, path := range []string{path, "/sandboxes/" + id + "/logs", "/v2/sandboxes/sandboxd-00000000000000000000000000000000/logs"} {
		got := request(t, s, http.MethodGet, path, nil)
		if failure := decodeBody[e2bError](t, got.Body); got.Code != http.StatusNotFound || failure.Code != http.StatusNotFound {
			t.Errorf("logs of a gone sandbox %s: %d %s", path, got.Code, got.Body.String())
		}
	}
}
