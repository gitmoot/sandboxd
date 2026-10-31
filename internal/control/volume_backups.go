package control

import (
	"context"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// serveVolumeTransfers runs after the normal control API authentication. Raw
// block backups are operator-only credentials, never customer-safe file exports.
func (s *Service) serveVolumeTransfers(w http.ResponseWriter, r *http.Request) bool {
	id, backup := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/volumes/"), "/backup")
	restore := r.URL.Path == "/volumes/restore"
	if !restore && (!strings.HasPrefix(r.URL.Path, "/volumes/") || !backup) {
		return false
	}
	if r.Method != http.MethodPost {
		s.fail(w, ProfileE2B, http.StatusMethodNotAllowed, "method not allowed")
		return true
	}
	native, ok := s.volumes.(vm.VolumeBackups)
	if !ok {
		s.fail(w, ProfileE2B, http.StatusNotImplemented, "native volume backups unavailable")
		return true
	}
	if !restore && (!vm.ValidVolumeID(id) || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.RawQuery != "") {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "backup requires a volume ID and no body or query")
		return true
	}
	select {
	case s.volumeTransferSlots <- struct{}{}:
		defer func() { <-s.volumeTransferSlots }()
	default:
		s.fail(w, ProfileE2B, http.StatusTooManyRequests, "too many volume transfers")
		return true
	}
	deadline := time.Now().Add(vm.VolumeTransferTimeout)
	ctx, cancel := context.WithDeadline(r.Context(), deadline)
	defer cancel()
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.fail(w, ProfileE2B, 503, "transfer deadlines unavailable")
		return true
	}
	if err := controller.SetWriteDeadline(deadline); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.fail(w, ProfileE2B, 503, "transfer deadlines unavailable")
		return true
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
		close(stopped)
	})
	defer func() {
		if !stop() {
			<-stopped
		}
		_ = controller.SetReadDeadline(time.Time{})
		_ = controller.SetWriteDeadline(time.Time{})
	}()
	if restore {
		contentType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		if err != nil || queryErr != nil || contentType != vm.VolumeBackupMediaType || len(params) != 0 || len(query) != 2 || len(query["name"]) != 1 || !vm.ValidVolumeName(query.Get("name")) || len(query["sourceVolumeID"]) != 1 || !vm.ValidVolumeID(query.Get("sourceVolumeID")) {
			s.fail(w, ProfileE2B, http.StatusBadRequest, "restore requires backup media type, new name and expected sourceVolumeID")
			return true
		}
		manifest, err := vm.ReadVolumeManifest(r.Body)
		if err != nil || manifest.SourceVolumeID != query.Get("sourceVolumeID") {
			s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid volume backup manifest")
			return true
		}
		volume, err := native.RestoreVolume(ctx, query.Get("name"), manifest, r.Body)
		if err != nil {
			s.volumeFailure(w, "restore", err)
			return true
		}
		jsonResponse(w, http.StatusCreated, s.withToken(volume))
		return true
	}
	snapshot, err := native.OpenVolumeBackup(ctx, id)
	if err != nil {
		s.volumeFailure(w, "backup", err)
		return true
	}
	defer snapshot.Data.Close()
	w.Header().Set("Content-Type", vm.VolumeBackupMediaType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := vm.WriteVolumeManifest(w, snapshot.Manifest); err != nil {
		log.Printf("volume backup manifest transfer failed: %v", err)
		panic(http.ErrAbortHandler)
	}
	// Disk size was checked before headers; copy exactly that many bytes. A
	// failed stream aborts the response rather than appending an error to a backup.
	count, err := io.CopyBuffer(w, io.LimitReader(snapshot.Data, snapshot.Manifest.SizeBytes), make([]byte, 64<<10))
	if err != nil || count != snapshot.Manifest.SizeBytes || ctx.Err() != nil {
		log.Printf("volume backup transfer incomplete: bytes=%d error=%v", count, err)
		panic(http.ErrAbortHandler)
	}
	return true
}
