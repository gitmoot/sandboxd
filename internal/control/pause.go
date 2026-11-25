package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gitmoot/sandboxd/internal/store"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// DefaultPauseRetention is Config.PauseRetention when unset.
const DefaultPauseRetention = 24 * time.Hour

// defaultResumeTimeout is E2B's ResumedSandbox timeout default in seconds.
const defaultResumeTimeout = 15

// A paused sandbox's row moves running → pausing → paused, and back through
// resuming. pausing and resuming rows are busy while the driver call runs:
// reconciliation leaves them alone, every other action is refused (409) and
// GET still describes them. A paused row holds its slot and capacity until
// it is resumed, deleted, or its retention (Config.PauseRetention, kept as
// the row's end time) lapses; reconciliation then destroys it like any
// expired sandbox. A failed pause or resume leaves the row in its prior
// state, and reconciliation destroys a VM that is no longer in it. Once
// Close starts, pauses and resumes are refused (503), and Close waits for
// those in flight to settle their rows before it closes the ledger.

type pauseRequest struct {
	Memory *bool `json:"memory"`
}

type resumeRequest struct {
	Timeout   *int64 `json:"timeout"`
	AutoPause *bool  `json:"autoPause"`
	Memory    *bool  `json:"memory"`
}

// pausable checks that a pause or resume names a present e2b sandbox on the
// local worker, answering the request otherwise.
func (s *Service) pausable(w http.ResponseWriter, r *http.Request, id string) bool {
	if !validID(id) {
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
		return false
	}
	row, m, err := s.present(r.Context(), id)
	if err != nil {
		s.fail(w, ProfileE2B, statusFor(err), fmt.Sprintf("sandbox %q unavailable", id))
		return false
	}
	if profile := rowProfile(row.Profile); profile != ProfileE2B {
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q uses the %s profile, which cannot pause", id, profile))
		return false
	}
	if !m.local {
		s.refuse(w, refusePauseRemote)
		return false
	}
	return true
}

// pause answers POST /sandboxes/{id}/pause: 204 once the sandbox is paused,
// 409 when it is already paused (the SDKs then report false).
func (s *Service) pause(w http.ResponseWriter, r *http.Request, id string) {
	var request pauseRequest
	if !readJSON(w, r, &request) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid pause request body")
		return
	}
	if request.Memory != nil && !*request.Memory {
		s.refuse(w, refusePauseFilesystem)
		return
	}
	if !s.pausable(w, r, id) {
		return
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "service closing")
		return
	}
	row, err := s.ledger.Get(r.Context(), id)
	switch {
	case err != nil || released(row):
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
		return
	case row.State == "paused" || row.State == "pausing" || row.State == "resuming":
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is already paused", id))
		return
	case row.State != "running" || s.busy[id] != nil:
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is not running", id))
		return
	}
	if err := s.setState(r.Context(), id, "pausing"); err != nil {
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	s.markBusy(id)
	s.lifecycle.Add(1)
	s.mu.Unlock()
	defer s.lifecycle.Done()
	if err := s.pauseRow(context.WithoutCancel(r.Context()), row, true); err != nil {
		log.Printf("sandbox %s: pause failed: %v", id, err)
		switch {
		case errors.Is(err, vm.ErrImageTooOld):
			s.fail(w, ProfileE2B, http.StatusInternalServerError, "template image does not support pause; the operator must rebuild it")
		case errors.Is(err, vm.ErrNotRunning):
			s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is not running", id))
		default:
			s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox pause failed")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pauseRow pauses row's VM, whose row the caller set pausing and busy, and
// settles the row: paused until its retention lapses on success. On failure
// an explicit pause (revert) returns the row to running, and reconciliation
// destroys the VM if the driver left it stopped; a failed auto-pause marks
// the row unknown, so reconciliation destroys it as at any end time.
func (s *Service) pauseRow(ctx context.Context, row store.Row, revert bool) error {
	pauseCtx, cancel := context.WithTimeout(ctx, workerSlowTimeout)
	pauseErr := s.pauser.Pause(pauseCtx, row.ID)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearBusy(row.ID)
	if pauseErr == nil {
		paused, err := s.ledger.Transition(ctx, row.ID, "pausing", "paused", time.Now().UTC().Add(s.cfg.PauseRetention), row.AutoPause)
		if err == nil && !paused {
			err = errors.New("sandbox row left pausing during the pause")
		}
		return err
	}
	if !revert {
		return errors.Join(pauseErr, s.setState(ctx, row.ID, "unknown"))
	}
	running, err := s.ledger.Transition(ctx, row.ID, "pausing", "running", row.Ends, row.AutoPause)
	if err == nil && running {
		s.indexSigner(row.ID)
	}
	return errors.Join(pauseErr, err)
}

// autoPause pauses an e2b sandbox with autoPause at its end time;
// reconciliation set its row pausing and busy, and counted it in lifecycle.
func (s *Service) autoPause(row store.Row) {
	defer s.lifecycle.Done()
	if err := s.pauseRow(context.Background(), row, false); err != nil {
		log.Printf("sandbox %s: auto-pause failed, destroying it: %v", row.ID, err)
	}
}

// resume answers POST /sandboxes/{id}/resume: 201 with the sandbox once it
// runs again, 409 when it is not paused.
func (s *Service) resume(w http.ResponseWriter, r *http.Request, id string) {
	var request resumeRequest
	if !readJSON(w, r, &request) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid resume request body")
		return
	}
	seconds := min(int64(defaultResumeTimeout), int64(s.cfg.MaxTTL/time.Second))
	if request.Timeout != nil {
		seconds = *request.Timeout
	}
	ttl, ok := s.ttl(seconds)
	if !ok {
		s.fail(w, ProfileE2B, http.StatusBadRequest, fmt.Sprintf("timeout must be between 1 and %d seconds", int64(s.cfg.MaxTTL/time.Second)))
		return
	}
	if request.Memory != nil && !*request.Memory {
		s.refuse(w, refusePauseFilesystem)
		return
	}
	if !s.pausable(w, r, id) {
		return
	}
	s.resumeSandbox(w, r, id, ttl, request.AutoPause)
}

// resumeSandbox resumes paused sandbox id for ttl and answers 201 with it;
// autoPause, when set, replaces the sandbox's choice. The caller checked
// that id is a present e2b sandbox on the local worker.
func (s *Service) resumeSandbox(w http.ResponseWriter, r *http.Request, id string, ttl time.Duration, autoPause *bool) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "service closing")
		return
	}
	row, err := s.ledger.Get(r.Context(), id)
	switch {
	case err != nil || released(row):
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusNotFound, fmt.Sprintf("sandbox %q not found", id))
		return
	case row.State == "running" && s.busy[id] == nil:
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is already running", id))
		return
	case row.State != "paused" || s.busy[id] != nil:
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is being paused or resumed", id))
		return
	}
	if err := s.setState(r.Context(), id, "resuming"); err != nil {
		s.mu.Unlock()
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	s.markBusy(id)
	s.lifecycle.Add(1)
	s.mu.Unlock()
	defer s.lifecycle.Done()

	ctx := context.WithoutCancel(r.Context())
	resumeCtx, cancel := context.WithTimeout(ctx, workerSlowTimeout)
	resumeErr := s.pauser.Resume(resumeCtx, id)
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearBusy(id)
	if resumeErr != nil {
		log.Printf("sandbox %s: resume failed: %v", id, resumeErr)
		if _, err := s.ledger.Transition(ctx, id, "resuming", "paused", row.Ends, row.AutoPause); err != nil {
			log.Printf("sandbox %s: record failed resume: %v", id, err)
		}
		switch {
		case errors.Is(resumeErr, vm.ErrMemoryPressure):
			s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "worker host memory is below its floor; retry later")
		case errors.Is(resumeErr, vm.ErrNotPaused):
			s.fail(w, ProfileE2B, http.StatusConflict, fmt.Sprintf("sandbox %q is not paused", id))
		default:
			s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox resume failed")
		}
		return
	}
	if autoPause != nil {
		row.AutoPause = *autoPause
	}
	row.State, row.Ends = "running", time.Now().UTC().Add(ttl)
	running, err := s.ledger.Transition(ctx, id, "resuming", "running", row.Ends, row.AutoPause)
	if err != nil || !running {
		// The row stays resuming and settled: reconciliation destroys the VM.
		log.Printf("sandbox %s: record resume: %v (row moved: %t)", id, err, !running)
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "sandbox state unavailable")
		return
	}
	s.indexSigner(id)
	jsonResponse(w, http.StatusCreated, s.e2bResponse(row))
}
