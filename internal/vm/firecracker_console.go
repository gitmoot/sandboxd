//go:build linux

package vm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var _ ConsoleReader = (*FirecrackerDriver)(nil)

// consoleSink returns the VMM's console descriptor for spec and, for an envd
// guest, the read end of the pipe behind it. With ConsoleLog the console goes
// to <jail>/console.log for debugging, as before, and is not kept for the
// logs API; a strict guest's console is discarded. The caller closes console
// once the jailer has started the VMM, which holds its own copy.
func (d *FirecrackerDriver) consoleSink(spec Spec) (console, capture *os.File, err error) {
	switch {
	case d.cfg.ConsoleLog:
		console, err = os.OpenFile(filepath.Join(d.jailDir(spec.ID), "console.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		return console, nil, err
	case spec.Envd:
		capture, console, err = os.Pipe()
		return console, capture, err
	}
	return nil, nil, nil
}

// captureConsole keeps what the VMM writes to the pipe read by capture in a
// bounded Console until the VMM exits. A daemon restart loses the reader: the
// VMM's later console writes then fail (EPIPE) and are dropped by its serial
// device, and Console reports ErrNoConsole for the adopted VM.
func (d *FirecrackerDriver) captureConsole(id string, capture *os.File) {
	console := NewConsole()
	d.consoleMu.Lock()
	if d.consoles == nil {
		d.consoles = make(map[string]*Console)
	}
	d.consoles[id] = console
	d.consoleMu.Unlock()
	go func() {
		_, _ = io.Copy(console, capture)
		_ = capture.Close()
	}()
}

func (d *FirecrackerDriver) dropConsole(id string) {
	d.consoleMu.Lock()
	delete(d.consoles, id)
	d.consoleMu.Unlock()
}

// Console returns a running envd guest's console output: envd's structured
// logs (envd runs with -verbose) and whatever else the guest writes to its
// serial console.
func (d *FirecrackerDriver) Console(_ context.Context, id string) ([]ConsoleLine, error) {
	if err := d.running(id); err != nil {
		return nil, err
	}
	d.consoleMu.Lock()
	console := d.consoles[id]
	d.consoleMu.Unlock()
	if console == nil {
		return nil, fmt.Errorf("Firecracker VM %q: %w", id, ErrNoConsole)
	}
	return console.Lines(), nil
}
