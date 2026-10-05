//go:build linux

package vm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var _ ConsoleReader = (*FirecrackerDriver)(nil)

// Bounds of the VMM startup output a failed Create reports.
const (
	fcStartupLines = 64
	fcStartupBytes = 16 << 10
	// fcStartupDrain bounds the wait for the rest of a failed VMM's output
	// once its VM has been destroyed.
	fcStartupDrain = time.Second
)

// fcStartup keeps the head of one VMM's stdout and stderr, the guest serial
// console: the first fcStartupLines lines and at most fcStartupBytes. When
// Firecracker fails to start it writes its panic there, and the jailer writes
// its own errors there too. The output is guest-controlled, so a failed
// Create puts it, quoted, only into the error the worker and gateway log; no
// API response carries driver error text.
type fcStartup struct {
	mu    sync.Mutex
	head  []byte
	lines int
	// eof, when set, is closed once the VMM's output reaches end of file.
	eof chan struct{}
}

// Write keeps what fits in the bounds and drops the rest. It never fails,
// so the VMM is never blocked by its own console.
func (s *fcStartup) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	written := len(p)
	for len(p) > 0 && s.lines < fcStartupLines && len(s.head) < fcStartupBytes {
		line := p
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line = p[:i+1]
		}
		line = line[:min(len(line), fcStartupBytes-len(s.head))]
		s.head = append(s.head, line...)
		if line[len(line)-1] == '\n' {
			s.lines++
		}
		p = p[len(line):]
	}
	return written, nil
}

// readFile keeps the head of the console file at path. With ConsoleLog the
// VMM writes the file itself, bounded by its fsize limit.
func (s *fcStartup) readFile(path string) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = io.Copy(s, io.LimitReader(file, fcStartupBytes))
}

// annotate adds the kept output to err, the cause of a failed Create.
func (s *fcStartup) annotate(err error) error {
	if s.eof != nil {
		select {
		case <-s.eof:
		case <-time.After(fcStartupDrain):
		}
	}
	s.mu.Lock()
	head := string(s.head)
	s.mu.Unlock()
	if head == "" {
		return err
	}
	return fmt.Errorf("%w\nVMM startup output (guest-controlled): %q", err, head)
}

func (d *FirecrackerDriver) consoleLogPath(id string) string {
	return filepath.Join(d.jailDir(id), "console.log")
}

// consoleSink returns the VMM's stdout and stderr for spec and, for an envd
// guest, the Console that keeps its output for the logs API. With ConsoleLog
// the VMM writes to <jail>/console.log for debugging, as before, and nothing
// is kept for the logs API. Otherwise the VMM writes to a pipe whose reader
// keeps the startup head in startup and the rest in the envd guest's Console
// (discarded for a strict guest) until the VMM exits. A daemon restart loses
// the reader: the VMM's later console writes then fail (EPIPE) and are
// dropped by its serial device, and Console reports ErrNoConsole for the
// adopted VM. The caller closes console once the jailer has started the VMM,
// which holds its own copy.
func (d *FirecrackerDriver) consoleSink(spec Spec, startup *fcStartup) (console *os.File, guest *Console, err error) {
	if d.cfg.ConsoleLog {
		console, err = os.OpenFile(d.consoleLogPath(spec.ID), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		return console, nil, err
	}
	capture, console, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	rest := io.Discard
	if spec.Envd {
		guest = NewConsole()
		rest = guest
	}
	startup.eof = make(chan struct{})
	go func() {
		_, _ = io.Copy(io.MultiWriter(startup, rest), capture)
		_ = capture.Close()
		close(startup.eof)
	}()
	return console, guest, nil
}

// keepConsole serves an envd guest's console through Console.
func (d *FirecrackerDriver) keepConsole(id string, console *Console) {
	d.consoleMu.Lock()
	if d.consoles == nil {
		d.consoles = make(map[string]*Console)
	}
	d.consoles[id] = console
	d.consoleMu.Unlock()
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
