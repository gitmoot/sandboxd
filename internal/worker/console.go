package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// maxConsoleBody bounds a console response: vm.ConsoleMaxBytes of text,
// at most doubled by JSON escaping, plus per-line framing.
const maxConsoleBody = 8 << 20

func (l *local) Console(ctx context.Context, id string) ([]vm.ConsoleLine, error) {
	reader, ok := l.Driver.(vm.ConsoleReader)
	if !ok {
		return nil, vm.ErrNoConsole
	}
	return reader.Console(ctx, id)
}

// console returns VM id's kept console lines; 404 when the driver keeps none
// for it, 501 when it keeps none at all.
func (s *Server) console(w http.ResponseWriter, r *http.Request, id string, _ context.Context) {
	reader, ok := s.driver.(vm.ConsoleReader)
	if !ok {
		http.Error(w, vm.ErrNoConsole.Error(), http.StatusNotImplemented)
		return
	}
	lines, err := reader.Console(r.Context(), id)
	if errors.Is(err, vm.ErrNoConsole) {
		http.Error(w, vm.ErrNoConsole.Error(), http.StatusNotFound)
		return
	}
	if err != nil {
		driverFailed(w, "console", err)
		return
	}
	if lines == nil {
		lines = []vm.ConsoleLine{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(lines)
}

// Console returns VM id's console lines kept by the worker's driver, or
// vm.ErrNoConsole when it keeps none for the VM.
func (c *Client) Console(ctx context.Context, id string) ([]vm.ConsoleLine, error) {
	if err := c.checkVM(id); err != nil {
		return nil, err
	}
	resp, err := c.leased(ctx, http.MethodGet, "/vms/"+id+"/console", nil, nil, 0, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotImplemented || resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("worker %s: %w", c.id, vm.ErrNoConsole)
	}
	if err := c.expect(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var lines []vm.ConsoleLine
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxConsoleBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lines); err != nil {
		return nil, fmt.Errorf("worker %s: console: %w", c.id, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("worker %s: console: trailing data after JSON response", c.id)
	}
	return lines, nil
}
