package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gitmoot/sandboxd/internal/guestagent"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// volumeEntry is E2B's Volume, the list item.
type volumeEntry struct {
	ID   string `json:"volumeID"`
	Name string `json:"name"`
}

// volumeAndToken is E2B's VolumeAndToken, the create and get response. It
// has no domain: the SDKs then use their own, and the content API they
// would reach there is refused anyway.
type volumeAndToken struct {
	volumeEntry
	Token string `json:"token"`
}

type newVolumeRequest struct {
	Name string `json:"name"`
}

// volumeToken is the token the SDKs require with a volume. It grants
// nothing: the volume content API it would authorize is refused, and a
// volume's data is reached only from a sandbox it is mounted in.
func (s *Service) volumeToken(id string) string {
	return s.derive("sandboxd volume token v1", id)
}

func (s *Service) withToken(volume vm.Volume) volumeAndToken {
	return volumeAndToken{volumeEntry{volume.ID, volume.Name}, s.volumeToken(volume.ID)}
}

// serveVolumes answers E2B's volume API when volumes are configured, and
// reports whether path was a volume route.
func (s *Service) serveVolumes(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	switch {
	case path == "/volumecontent" || strings.HasPrefix(path, "/volumecontent/"):
		s.refuse(w, refuseVolumeContent)
	case path == "/volumes":
		switch r.Method {
		case http.MethodGet:
			s.listVolumes(w, r)
		case http.MethodPost:
			s.createVolume(w, r)
		default:
			s.fail(w, ProfileE2B, http.StatusMethodNotAllowed, "method not allowed")
		}
	case strings.HasPrefix(path, "/volumes/"):
		id := path[len("/volumes/"):]
		if !vm.ValidVolumeID(id) {
			s.fail(w, ProfileE2B, http.StatusNotFound, "volume not found")
			return true
		}
		switch r.Method {
		case http.MethodGet:
			s.getVolume(w, r, id)
		case http.MethodDelete:
			s.deleteVolume(w, r, id)
		default:
			s.fail(w, ProfileE2B, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		return false
	}
	return true
}

// volumeFailure answers a driver error: the vm sentinels as the client's
// own conflict or mistake, anything else as unavailable. Driver detail can
// name host paths, so it goes to the log only.
func (s *Service) volumeFailure(w http.ResponseWriter, action string, err error) {
	switch {
	case errors.Is(err, vm.ErrVolumeNotFound):
		s.fail(w, ProfileE2B, http.StatusNotFound, "volume not found")
	case errors.Is(err, vm.ErrVolumeExists):
		s.fail(w, ProfileE2B, http.StatusConflict, "a volume with that name already exists")
	case errors.Is(err, vm.ErrVolumeInUse):
		s.fail(w, ProfileE2B, http.StatusConflict, "volume is attached to a sandbox: kill the sandbox first")
	case errors.Is(err, vm.ErrVolumeBudget):
		// 400 is the only client error the SDKs declare for create.
		s.fail(w, ProfileE2B, http.StatusBadRequest, "volume budget exhausted: delete a volume first")
	default:
		log.Printf("volume %s: %v", action, err)
		s.fail(w, ProfileE2B, http.StatusServiceUnavailable, "volume state unavailable")
	}
}

func (s *Service) createVolume(w http.ResponseWriter, r *http.Request) {
	var request newVolumeRequest
	if err := decode(w, r, &request); !errors.Is(err, io.EOF) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid volume request body")
		return
	}
	if !vm.ValidVolumeName(request.Name) {
		s.fail(w, ProfileE2B, http.StatusBadRequest, "invalid volume name: 1-63 letters, digits, '_' or '-', starting with a letter or digit")
		return
	}
	volume, err := s.volumes.CreateVolume(r.Context(), request.Name)
	if err != nil {
		s.volumeFailure(w, "create", err)
		return
	}
	jsonResponse(w, http.StatusCreated, s.withToken(volume))
}

func (s *Service) listVolumes(w http.ResponseWriter, r *http.Request) {
	volumes, err := s.volumes.Volumes(r.Context())
	if err != nil {
		s.volumeFailure(w, "list", err)
		return
	}
	entries := make([]volumeEntry, 0, len(volumes))
	for _, volume := range volumes {
		entries = append(entries, volumeEntry{volume.ID, volume.Name})
	}
	jsonResponse(w, http.StatusOK, entries)
}

func (s *Service) getVolume(w http.ResponseWriter, r *http.Request, id string) {
	volumes, err := s.volumes.Volumes(r.Context())
	if err != nil {
		s.volumeFailure(w, "get", err)
		return
	}
	for _, volume := range volumes {
		if volume.ID == id {
			jsonResponse(w, http.StatusOK, s.withToken(volume))
			return
		}
	}
	s.fail(w, ProfileE2B, http.StatusNotFound, "volume not found")
}

func (s *Service) deleteVolume(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.volumes.DeleteVolume(r.Context(), id); err != nil {
		s.volumeFailure(w, "delete", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// volumeMountRequest is E2B's SandboxVolumeMount.
type volumeMountRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// volumeMount resolves createV2's volumeMounts to the one mount the VM
// gets, or nil for none. A nonzero status refuses the request before any
// slot is reserved. Callers have refused volumeMounts unless volumes are on.
// A hardened guest's root is read-only, so its mount point must lie below
// its writable home.
func (s *Service) volumeMount(ctx context.Context, raw json.RawMessage, hardened bool) (*vm.VolumeMount, int, string) {
	if absent(raw) {
		return nil, 0, ""
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var mounts []volumeMountRequest
	if err := decoder.Decode(&mounts); err != nil {
		return nil, http.StatusBadRequest, "invalid volumeMounts: a list of {name, path}"
	}
	switch {
	case len(mounts) == 0:
		return nil, 0, ""
	case len(mounts) > 1:
		return nil, http.StatusBadRequest, "at most one volume mount per sandbox"
	}
	requested := mounts[0]
	if !vm.ValidMountPath(requested.Path) {
		return nil, http.StatusBadRequest, fmt.Sprintf("invalid volume mount path %q: an absolute, clean path other than / of letters, digits and ._/-", requested.Path)
	}
	if hardened && !vm.ValidHardenedMountPath(requested.Path) {
		return nil, http.StatusBadRequest, fmt.Sprintf("invalid volume mount path %q: a hardened template's system disk is read-only, so volumes mount only below %s", requested.Path, guestagent.HardenedHome)
	}
	if !vm.ValidVolumeName(requested.Name) {
		return nil, http.StatusBadRequest, fmt.Sprintf("invalid volume name %q", requested.Name)
	}
	volumes, err := s.volumes.Volumes(ctx)
	if err != nil {
		log.Printf("volume mount: %v", err)
		return nil, http.StatusServiceUnavailable, "volume state unavailable"
	}
	for _, volume := range volumes {
		if volume.Name != requested.Name {
			continue
		}
		// A courtesy check: the driver refuses an attached volume
		// authoritatively at Create, after a slot is reserved.
		if volume.AttachedTo != "" {
			return nil, http.StatusConflict, fmt.Sprintf("volume %q is attached to sandbox %s", volume.Name, volume.AttachedTo)
		}
		return &vm.VolumeMount{ID: volume.ID, Path: requested.Path}, 0, ""
	}
	return nil, http.StatusNotFound, fmt.Sprintf("volume %q not found", requested.Name)
}
