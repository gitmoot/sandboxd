package control

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/worker"
)

// e2bError is the E2B API error body the SDKs parse.
type e2bError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// fail writes an error in the profile's format: E2B's JSON error for e2b,
// the original plain text for gitmoot-strict.
func (s *Service) fail(w http.ResponseWriter, profile Profile, status int, message string) {
	if profile != ProfileE2B {
		http.Error(w, message, status)
		return
	}
	jsonResponse(w, status, e2bError{Code: status, Message: message})
}

// profileOf is the error format for a per-sandbox request: the row's profile,
// or the shared one for an unknown ID. Callers do not hold s.mu.
func (s *Service) profileOf(ctx context.Context, id string) Profile {
	s.mu.Lock()
	row, err := s.ledger.Get(ctx, id)
	s.mu.Unlock()
	if err != nil {
		return s.templates.sharedProfile()
	}
	return rowProfile(row.Profile)
}

// envdToken derives an e2b sandbox's envd access token, so connect can return
// it again while the ledger stores only its hash.
func (s *Service) envdToken(id string) string {
	return s.derive("sandboxd envd access token v1", id)
}

// trafficToken derives an e2b sandbox's traffic access token, which grants
// its exposed guest ports and nothing else.
func (s *Service) trafficToken(id string) string {
	return s.derive("sandboxd traffic access token v1", id)
}

func (s *Service) derive(label, id string) string {
	mac := hmac.New(sha256.New, s.tokenKey)
	mac.Write([]byte(label + "\x00" + id))
	return hex.EncodeToString(mac.Sum(nil))
}

// e2bSandbox is the create/connect response the SDKs require.
type e2bSandbox struct {
	ID              string `json:"sandboxID"`
	TemplateID      string `json:"templateID"`
	ClientID        string `json:"clientID"`
	EnvdVersion     string `json:"envdVersion"`
	EnvdAccessToken string `json:"envdAccessToken"`
	// TrafficAccessToken is always issued: guest ports are never public
	// (E2B's allowPublicTraffic=false).
	TrafficAccessToken string `json:"trafficAccessToken"`
	Domain             string `json:"domain"`
}

func (s *Service) e2bResponse(row store.Row) e2bSandbox {
	return e2bSandbox{ID: row.ID, TemplateID: row.TemplateID, ClientID: clientID, EnvdVersion: s.describe(row).EnvdVersion,
		EnvdAccessToken: s.envdToken(row.ID), TrafficAccessToken: s.trafficToken(row.ID), Domain: s.cfg.Domain}
}

// createV2Request is the SDK 2.52.0 NewSandboxV2 body. Every field is known,
// so an option a newer SDK adds is refused rather than silently ignored.
type createV2Request struct {
	TemplateID          string            `json:"templateID"`
	Timeout             *int64            `json:"timeout"`
	AutoPause           *bool             `json:"autoPause"`
	AutoPauseMemory     json.RawMessage   `json:"autoPauseMemory"`
	AutoResume          json.RawMessage   `json:"autoResume"`
	Secure              *bool             `json:"secure"`
	AllowInternetAccess json.RawMessage   `json:"allow_internet_access"`
	Network             json.RawMessage   `json:"network"`
	Metadata            map[string]string `json:"metadata"`
	EnvVars             map[string]string `json:"envVars"`
	MCP                 json.RawMessage   `json:"mcp"`
	IAM                 json.RawMessage   `json:"iam"`
	VolumeMounts        json.RawMessage   `json:"volumeMounts"`
}

// defaultTimeout is the SDKs' default sandbox lifetime in seconds.
const defaultTimeout = 300

func absent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// unsupported names the first requested option sandboxd cannot honour yet.
func (request createV2Request) unsupported() string {
	switch {
	case request.AutoPause != nil && *request.AutoPause:
		return "autoPause (pause and resume) is not supported"
	case !absent(request.AutoResume) && string(request.AutoResume) != `{"enabled":false}`:
		return "autoResume is not supported"
	case request.Secure != nil && !*request.Secure:
		return "every sandbox requires its envd access token; secure=false is not supported"
	case !absent(request.AllowInternetAccess), !absent(request.Network) && !privateTraffic(request.Network):
		return "network and internet access options are not supported (guest ports are never public: only network.allowPublicTraffic=false is accepted)"
	case !absent(request.MCP):
		return "MCP gateways are not supported"
	case !absent(request.IAM):
		return "IAM options are not supported"
	case !absent(request.VolumeMounts):
		return "volume mounts are not supported"
	}
	return ""
}

// privateTraffic reports whether network asks for exactly what sandboxd
// always does: guest ports reachable only with the traffic access token.
func privateTraffic(network json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(network))
	decoder.DisallowUnknownFields()
	var options struct {
		AllowPublicTraffic *bool `json:"allowPublicTraffic"`
	}
	return decoder.Decode(&options) == nil && !decoder.More() && options.AllowPublicTraffic != nil && !*options.AllowPublicTraffic
}

func (s *Service) createV2(w http.ResponseWriter, r *http.Request) {
	var request createV2Request
	if err := decode(w, r, &request); !errors.Is(err, io.EOF) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid sandbox request body")
		return
	}
	template, ok := s.templates.lookup(request.TemplateID)
	if !ok {
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("template %q not found", request.TemplateID))
		return
	}
	if template.Profile != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusBadRequest, fmt.Sprintf("template %q uses the %s profile; create it with POST /sandboxes", request.TemplateID, template.Profile))
		return
	}
	if reason := request.unsupported(); reason != "" {
		s.fail(w, ProfileE2B, http.StatusBadRequest, reason)
		return
	}
	seconds := min(int64(defaultTimeout), int64(s.cfg.MaxTTL/time.Second))
	if request.Timeout != nil {
		seconds = *request.Timeout
	}
	ttl, ok := s.ttl(seconds)
	if !ok {
		s.fail(w, ProfileE2B, http.StatusBadRequest, fmt.Sprintf("timeout must be between 1 and %d seconds", int64(s.cfg.MaxTTL/time.Second)))
		return
	}
	// Owner metadata is optional; when present it is the same job fence as
	// the strict profile's.
	var fence owner
	if _, ok := request.Metadata["job_id"]; ok {
		if fence, ok = parseOwner(request.Metadata); !ok {
			s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid sandbox owner metadata")
			return
		}
	}
	metadata := request.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid metadata")
		return
	}
	idBytes, err := randomHex(16)
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	id := "sandboxd-" + idBytes
	hash := sha256.Sum256([]byte(s.envdToken(id)))
	started := time.Now().UTC()
	row := store.Row{ID: id, TokenHash: hash[:], Metadata: string(encoded), JobID: fence.job,
		TemplateID: template.ID, Profile: string(ProfileE2B), Attempt: fence.attempt, Generation: fence.generation,
		Fence: metadata["daemon_fencing_token"], Started: started, Ends: started.Add(ttl)}
	if err := s.launch(r.Context(), &row); err != nil {
		var refusal *refusal
		if errors.As(err, &refusal) {
			s.fail(w, ProfileE2B, refusal.status, refusal.message)
		} else {
			s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		}
		return
	}
	// envd is the guest's entrypoint; until its /init the sandbox has
	// neither its access token nor its environment, so a failed /init ends
	// the sandbox. The envVars go to the guest and nowhere else.
	// Then the template's start command, if any, and its readiness: a
	// sandbox that is not ready is never returned.
	message := "sandbox envd did not start"
	err = s.initEnvd(r.Context(), id, request.EnvVars)
	if err == nil {
		message = "sandbox template did not become ready"
		err = s.startTemplate(r.Context(), id, template.Template)
	}
	if err != nil {
		log.Printf("sandbox %s: %s, destroying it: %v", id, message, err)
		abortCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), workerSlowTimeout)
		abortErr := s.Abort(abortCtx, id, s.envdToken(id))
		cancel()
		if abortErr != nil {
			log.Printf("sandbox %s: destroy after failed start: %v", id, abortErr)
		}
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, message)
		return
	}
	jsonResponse(w, http.StatusCreated, s.e2bResponse(row))
}

type connectRequest struct {
	Timeout *int64 `json:"timeout"`
	// Memory chooses how a paused sandbox resumes; nothing is ever paused.
	Memory json.RawMessage `json:"memory"`
}

// connect returns a running e2b sandbox's envd token again and extends its
// lifetime to at least timeout seconds from now; it never shortens it.
func (s *Service) connect(w http.ResponseWriter, r *http.Request, id string) {
	var request connectRequest
	if err := decode(w, r, &request); !errors.Is(err, io.EOF) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid connect request body")
		return
	}
	var ttl time.Duration
	if request.Timeout != nil {
		var ok bool
		if ttl, ok = s.ttl(*request.Timeout); !ok {
			s.fail(w, ProfileE2B, http.StatusBadRequest, fmt.Sprintf("timeout must be between 1 and %d seconds", int64(s.cfg.MaxTTL/time.Second)))
			return
		}
	}
	row, m, err := s.live(r.Context(), id)
	if err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return
	}
	if profile := rowProfile(row.Profile); profile != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q uses the %s profile, which has no connect", id, profile))
		return
	}
	if request.Timeout != nil {
		if end := time.Now().UTC().Add(ttl); end.After(row.Ends) {
			if err := s.extend(r.Context(), id, m, end, true); err != nil {
				s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
				return
			}
		}
	}
	jsonResponse(w, http.StatusOK, s.e2bResponse(row))
}

// e2bMetric is the SDK's SandboxMetric; every field is required.
type e2bMetric struct {
	Timestamp     string  `json:"timestamp"`
	TimestampUnix int64   `json:"timestampUnix"`
	CPUCount      int     `json:"cpuCount"`
	CPUUsedPct    float64 `json:"cpuUsedPct"`
	MemUsed       uint64  `json:"memUsed"`
	MemTotal      uint64  `json:"memTotal"`
	MemCache      uint64  `json:"memCache"`
	DiskUsed      uint64  `json:"diskUsed"`
	DiskTotal     uint64  `json:"diskTotal"`
}

// metricsE2B returns one current measured sample. sandboxd keeps no history:
// a window that ends before the sandbox started or begins in the future has
// no samples. Disk and page cache must be measured by the driver; they are
// never filled with invented values.
func (s *Service) metricsE2B(w http.ResponseWriter, r *http.Request, row store.Row, m *member) {
	query := r.URL.Query()
	bound := func(name string) (int64, bool, error) {
		values, ok := query[name]
		if !ok {
			return 0, false, nil
		}
		if len(values) != 1 {
			return 0, false, errors.New("repeated")
		}
		value, err := strconv.ParseInt(values[0], 10, 64)
		return value, true, err
	}
	start, hasStart, startErr := bound("start")
	end, hasEnd, endErr := bound("end")
	if startErr != nil || endErr != nil {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "start and end must be Unix seconds")
		return
	}
	now := time.Now().UTC()
	if hasEnd && end < row.Started.Unix() || hasStart && start > now.Unix() {
		jsonResponse(w, http.StatusOK, []e2bMetric{})
		return
	}
	usageCtx, cancel := context.WithTimeout(r.Context(), workerTimeout)
	defer cancel()
	usage, err := m.api.Usage(usageCtx, row.ID)
	if errors.Is(err, worker.ErrNoMetrics) {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "VM metrics unavailable")
		return
	}
	if err != nil {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	if !usage.Detailed {
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "this VM driver does not measure guest disk and page-cache use")
		return
	}
	jsonResponse(w, http.StatusOK, []e2bMetric{{
		Timestamp: now.Format(time.RFC3339Nano), TimestampUnix: now.Unix(), CPUCount: s.describe(row).CPUCount,
		CPUUsedPct: usage.CPUUsedPct, MemUsed: usage.MemoryUsedBytes, MemTotal: usage.MemoryLimitBytes,
		MemCache: usage.MemoryCacheBytes, DiskUsed: usage.DiskUsedBytes, DiskTotal: usage.DiskTotalBytes,
	}})
}

// listFilter is the SDK list query: metadata, state, template, startedAfter
// and order. Gitmoot sends none of them.
type listFilter struct {
	metadata     []metadataPair
	running      bool // the state filter admits running sandboxes
	template     string
	startedAfter time.Time
	order        string
}

func single(query url.Values, name string) (string, bool, error) {
	values, ok := query[name]
	if !ok {
		return "", false, nil
	}
	if len(values) != 1 {
		return "", false, fmt.Errorf("repeated %s parameter", name)
	}
	return values[0], true, nil
}

// metadataPair is one metadata filter term. Each side lists the forms it may
// take: the JS SDK URL-encodes every key and value once more before encoding
// the whole filter, the Python SDK does not, and neither says which it did.
// A term matches a row holding any of its key forms with any of its value
// forms, so a literal value such as "a%20b" still matches itself.
type metadataPair struct{ keys, values []string }

// encodingForms returns value as sent and, when it is itself well-formed
// URL encoding of a different string, that string.
func encodingForms(value string) []string {
	if unescaped, err := url.QueryUnescape(value); err == nil && unescaped != value {
		return []string{value, unescaped}
	}
	return []string{value}
}

func parseListFilter(query url.Values, templates *registry) (listFilter, error) {
	filter := listFilter{running: true}
	if raw, ok, err := single(query, "metadata"); err != nil {
		return filter, err
	} else if ok {
		pairs, err := url.ParseQuery(raw)
		if err != nil {
			return filter, errors.New("invalid metadata filter")
		}
		for key, values := range pairs {
			if len(values) != 1 {
				return filter, errors.New("invalid metadata filter")
			}
			filter.metadata = append(filter.metadata, metadataPair{keys: encodingForms(key), values: encodingForms(values[0])})
		}
	}
	if values, ok := query["state"]; ok {
		filter.running = false
		for _, value := range values {
			for _, state := range strings.Split(value, ",") {
				switch strings.TrimSpace(state) {
				case "running":
					filter.running = true
				case "paused":
				default:
					return filter, fmt.Errorf("invalid state filter %q", state)
				}
			}
		}
	}
	if name, ok, err := single(query, "template"); err != nil {
		return filter, err
	} else if ok {
		filter.template = name
		if template, known := templates.lookup(name); known {
			filter.template = template.ID
		}
	}
	if raw, ok, err := single(query, "startedAfter"); err != nil {
		return filter, err
	} else if ok {
		if filter.startedAfter, err = time.Parse(time.RFC3339Nano, raw); err != nil {
			return filter, errors.New("startedAfter must be an RFC 3339 time")
		}
	}
	if order, ok, err := single(query, "order"); err != nil {
		return filter, err
	} else if ok {
		if order != "asc" && order != "desc" {
			return filter, errors.New("order must be asc or desc")
		}
		filter.order = order
	}
	return filter, nil
}

// matches reports whether a row belongs to the filtered response, judging
// only its ledger fields: every listed sandbox is running, so a strict row
// that cannot be described is one the response may be missing.
func (f listFilter) matches(row store.Row) bool {
	if !f.running || f.template != "" && row.TemplateID != f.template ||
		!f.startedAfter.IsZero() && row.Started.Before(f.startedAfter) {
		return false
	}
	if len(f.metadata) == 0 {
		return true
	}
	var metadata map[string]string
	if json.Unmarshal([]byte(row.Metadata), &metadata) != nil {
		return false
	}
	for _, pair := range f.metadata {
		if !pair.matches(metadata) {
			return false
		}
	}
	return true
}

func (p metadataPair) matches(metadata map[string]string) bool {
	for _, key := range p.keys {
		if got, ok := metadata[key]; ok && slices.Contains(p.values, got) {
			return true
		}
	}
	return false
}

// listOrder returns the list's strict total order. Without an explicit order
// a service with e2b templates lists newest first, as E2B does; a strict-only
// service keeps its original sandbox-ID order.
func (s *Service) listOrder(order string) (before func(a, b sandbox) bool, byID bool) {
	switch {
	case order == "asc":
		return func(a, b sandbox) bool {
			return a.StartedAt.Before(b.StartedAt) || a.StartedAt.Equal(b.StartedAt) && a.ID < b.ID
		}, false
	case order == "desc" || s.templates.e2b:
		return func(a, b sandbox) bool {
			return a.StartedAt.After(b.StartedAt) || a.StartedAt.Equal(b.StartedAt) && a.ID < b.ID
		}, false
	}
	return func(a, b sandbox) bool { return a.ID < b.ID }, true
}

// cursor positions a next token: the last sandbox of the previous page,
// which may have gone since. Rows are never deleted from the ledger.
func (s *Service) cursor(ctx context.Context, token string, byID bool, result []sandbox) (sandbox, error) {
	if byID {
		return sandbox{ID: token}, nil
	}
	for _, item := range result {
		if item.ID == token {
			return item, nil
		}
	}
	row, err := s.ledger.Get(ctx, token)
	if err != nil {
		return sandbox{}, err
	}
	return sandbox{ID: row.ID, StartedAt: row.Started}, nil
}
