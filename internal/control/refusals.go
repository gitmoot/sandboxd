package control

import (
	"fmt"
	"net/http"
	"strings"
)

// notSupportedDoc is where every refusal points.
const notSupportedDoc = "see docs/compatibility.md#not-supported"

// E2B API features sandboxd refuses. Every route of such a feature answers
// 501 Not Implemented with E2B's JSON error and one of these messages, never
// a 404 route miss or a silent success, so the SDKs raise their generic API
// error (Python SandboxException, JS SandboxError; TemplateException and
// BuildError for template calls) with status 501 and this message. Only
// services with an e2b template answer them; a gitmoot-strict-only service
// keeps its plain 404.
const (
	refusePause     = "pause and resume are not supported: sandboxd never pauses a sandbox (deferred, owner decision D7)"
	refuseSnapshots = "snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (deferred with pause, D7)"
	refuseFork      = "fork is not supported: it needs snapshots (deferred with pause, D7)"
	refuseNetwork   = "network updates are not supported: a sandbox's network policy is fixed by the operator"
	refuseVolumes   = "volumes are not supported: sandboxd keeps no storage beyond a sandbox's lifetime"
	refuseSecrets   = "secrets are not supported: pass values to a sandbox in envVars instead"
	refuseTeams     = "teams are not supported: sandboxd has a single operator API key"
	refuseTemplates = "template builds and template management through the API are not supported: the operator builds and registers templates with the sandboxd CLI (D8)"
	// DELETE /templates/{id} deletes a template or, for the SDKs'
	// delete_snapshot, a snapshot.
	refuseTemplateDelete = "deleting templates or snapshots through the API is not supported: the operator registers templates with the sandboxd CLI (D8) and sandboxd has no snapshots (D7)"
)

// refuse answers a request for a feature sandboxd does not support.
func (s *Service) refuse(w http.ResponseWriter, reason string) {
	s.fail(w, ProfileE2B, http.StatusNotImplemented, reason+"; "+notSupportedDoc)
}

// sandboxRefusal names the refusal for a per-sandbox action, or "".
func sandboxRefusal(action string) string {
	switch action {
	case "pause", "resume":
		return refusePause
	case "snapshots":
		return refuseSnapshots
	case "fork":
		return refuseFork
	case "network":
		return refuseNetwork
	}
	return ""
}

// refusable checks that a refused per-sandbox action names a live sandbox,
// answering as every per-sandbox route does otherwise (404 for a gone or
// unknown sandbox, which the SDKs raise as not found; 503 when unobservable).
func (s *Service) refusable(w http.ResponseWriter, r *http.Request, id string) bool {
	if !validID(id) {
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
		return false
	}
	if _, _, err := s.live(r.Context(), id); err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return false
	}
	return true
}

// apiRefusal names the refusal for a request outside /sandboxes, or "".
// GET /templates/aliases/{alias} is served (templateAlias), not refused.
func apiRefusal(r *http.Request) string {
	path := r.URL.Path
	under := func(prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }
	switch {
	case under("/snapshots"):
		return refuseSnapshots
	case under("/volumes"), under("/volumecontent"):
		return refuseVolumes
	case under("/secrets"):
		return refuseSecrets
	case under("/teams"):
		return refuseTeams
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/templates/aliases/"):
		return ""
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/templates/") && !strings.Contains(path[len("/templates/"):], "/"):
		return refuseTemplateDelete
	case under("/templates"), under("/v2/templates"), under("/v3/templates"):
		return refuseTemplates
	}
	return ""
}

// templateAlias answers E2B's alias lookup (the SDKs' Template.exists) from
// the operator registry: any registered template ID or alias exists.
func (s *Service) templateAlias(w http.ResponseWriter, alias string) {
	template, ok := s.templates.lookup(alias)
	if !ok {
		s.fail(w, ProfileE2B, http.StatusNotFound, "template alias not found")
		return
	}
	jsonResponse(w, http.StatusOK, struct {
		TemplateID string `json:"templateID"`
		Public     bool   `json:"public"`
	}{template.ID, false})
}
