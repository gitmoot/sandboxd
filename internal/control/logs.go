package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// maxLogs is the most entries one logs response carries, and the default,
// as on E2B.
const maxLogs = 1000

// maxLogSearch bounds the logs search parameter.
const maxLogSearch = 1024

// logLevels are E2B's log levels, least severe first.
var logLevels = []string{"debug", "info", "warn", "error"}

// logEntry is E2B's SandboxLogEntry; every field is required.
type logEntry struct {
	Timestamp string            `json:"timestamp"`
	Level     string            `json:"level"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields"`
	rank      int
}

// v1LogLine is E2B's SandboxLog of the deprecated v1 logs route.
type v1LogLine struct {
	Line      string `json:"line"`
	Timestamp string `json:"timestamp"`
}

// logQuery is a logs request: from (inclusive, Unix milliseconds) or, going
// backward, until; a minimum level; a case-sensitive message substring.
type logQuery struct {
	cursor    int64
	hasCursor bool
	limit     int
	backward  bool
	minRank   int
	search    string
}

// parseLogQuery reads the v2 parameters (cursor, limit, direction, level,
// search) or the v1 ones (start, limit).
func parseLogQuery(r *http.Request, v2 bool) (logQuery, error) {
	query := r.URL.Query()
	q := logQuery{limit: maxLogs}
	known := map[string]bool{"limit": true, "start": !v2, "cursor": v2, "direction": v2, "level": v2, "search": v2}
	for name := range query {
		if !known[name] {
			return q, fmt.Errorf("unknown logs parameter %q", name)
		}
	}
	cursorName := "start"
	if v2 {
		cursorName = "cursor"
	}
	if raw, ok, err := single(query, cursorName); err != nil {
		return q, err
	} else if ok {
		if q.cursor, err = strconv.ParseInt(raw, 10, 64); err != nil || q.cursor < 0 {
			return q, fmt.Errorf("%s must be Unix milliseconds", cursorName)
		}
		q.hasCursor = true
	}
	if raw, ok, err := single(query, "limit"); err != nil {
		return q, err
	} else if ok {
		if q.limit, err = strconv.Atoi(raw); err != nil || q.limit < 0 || q.limit > maxLogs {
			return q, fmt.Errorf("limit must be between 0 and %d", maxLogs)
		}
	}
	if raw, ok, err := single(query, "direction"); err != nil {
		return q, err
	} else if ok {
		if raw != "forward" && raw != "backward" {
			return q, errors.New("direction must be forward or backward")
		}
		q.backward = raw == "backward"
	}
	if raw, ok, err := single(query, "level"); err != nil {
		return q, err
	} else if ok {
		if q.minRank = slices.Index(logLevels, raw); q.minRank < 0 {
			return q, errors.New("level must be debug, info, warn or error")
		}
	}
	if raw, ok, err := single(query, "search"); err != nil {
		return q, err
	} else if ok {
		if len(raw) > maxLogSearch {
			return q, fmt.Errorf("search must be at most %d bytes", maxLogSearch)
		}
		q.search = raw
	}
	return q, nil
}

// logs serves GET /v2/sandboxes/{id}/logs and the deprecated v1
// GET /sandboxes/{id}/logs of a running e2b sandbox: its guest console as
// kept by its worker, that is upstream envd's structured logs and any other
// console output, one entry per line. Logs end with the sandbox.
func (s *Service) logs(w http.ResponseWriter, r *http.Request, id string, v2 bool) {
	query, err := parseLogQuery(r, v2)
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusBadRequest, err.Error())
		return
	}
	row, m, err := s.live(r.Context(), id)
	if err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return
	}
	if profile := rowProfile(row.Profile); profile != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q uses the %s profile, which has no logs", id, profile))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	defer cancel()
	lines, err := m.api.Console(ctx, id)
	if errors.Is(err, vm.ErrNoConsole) {
		s.fail(w, ProfileE2B, http.StatusNotImplemented, fmt.Sprintf(
			"logs of sandbox %q are not available: its worker keeps no console output for it (its driver has none, the worker restarted since the sandbox started, or the console goes to a debugging file)", id))
		return
	}
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	entries := selectLogs(lines, query)
	if v2 {
		jsonResponse(w, http.StatusOK, struct {
			Logs []logEntry `json:"logs"`
		}{entries})
		return
	}
	plain := make([]v1LogLine, len(entries))
	for i, entry := range entries {
		plain[i] = v1LogLine{Line: entry.Message, Timestamp: entry.Timestamp}
	}
	jsonResponse(w, http.StatusOK, struct {
		Logs       []v1LogLine `json:"logs"`
		LogEntries []logEntry  `json:"logEntries"`
	}{plain, entries})
}

// selectLogs returns the entries query selects: forward from the cursor
// (inclusive) oldest first, or backward up to it newest first, at most
// query.limit of them.
func selectLogs(lines []vm.ConsoleLine, query logQuery) []logEntry {
	entries := make([]logEntry, 0, min(len(lines), query.limit))
	at := func(i int) vm.ConsoleLine {
		if query.backward {
			return lines[len(lines)-1-i]
		}
		return lines[i]
	}
	for i := range len(lines) {
		if len(entries) == query.limit {
			break
		}
		line := at(i)
		ms := line.Time.UnixMilli()
		if query.hasCursor && (!query.backward && ms < query.cursor || query.backward && ms > query.cursor) {
			continue
		}
		entry := parseLogLine(line)
		if entry.rank < query.minRank || !strings.Contains(entry.Message, query.search) {
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

// parseLogLine turns one console line into an entry stamped with the host
// time the line arrived (a guest's own clock is not trusted). A JSON object
// line is one of envd's structured logs: its level and message, and its
// remaining scalar fields as strings. Nested values, such as the RPC request
// bodies envd logs at debug level (which can carry a command's environment),
// are never served. Any other line is an info entry with the line as message.
func parseLogLine(line vm.ConsoleLine) logEntry {
	entry := logEntry{Timestamp: line.Time.UTC().Format(time.RFC3339Nano), Level: "info", Message: line.Text,
		Fields: map[string]string{}, rank: 1}
	if !strings.HasPrefix(line.Text, "{") {
		return entry
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(line.Text), &object) != nil {
		return entry
	}
	entry.Fields["source"] = "envd"
	for key, raw := range object {
		var text string
		isString := json.Unmarshal(raw, &text) == nil
		switch key {
		case "level":
			if isString {
				entry.Level, entry.rank = envdLevel(text)
			}
			continue
		case "message":
			if isString {
				entry.Message = text
			}
			continue
		case "timestamp", "time", "source":
			continue
		}
		switch {
		case isString:
			entry.Fields[key] = text
		case len(raw) > 0 && (raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9' || raw[0] == 't' || raw[0] == 'f'):
			entry.Fields[key] = string(raw)
		}
	}
	return entry
}

// envdLevel maps envd's zerolog level to E2B's LogLevel and its rank.
func envdLevel(level string) (string, int) {
	switch level {
	case "trace", "debug":
		return "debug", 0
	case "warn":
		return "warn", 2
	case "error", "fatal", "panic":
		return "error", 3
	}
	return "info", 1
}
