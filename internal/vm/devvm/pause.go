//go:build sandboxd_devdriver && linux

package devvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// A dev guest pauses in place: every process of it is stopped (SIGSTOP) and
// continued (SIGCONT) on resume, so its memory, processes, files and network
// are kept as they were. A paused guest runs no code but keeps its host RAM;
// it does not survive a driver restart (no dev guest does). Resume continues
// every process of the guest, also one the guest had stopped itself.

const (
	// envdPause and envdResume are the lifeline bytes that pause and resume
	// an envd guest (see envdInit).
	envdPause  byte = 'P'
	envdResume byte = 'R'
	// envdPausedMark exists in an envd guest's directory while its init
	// holds every other process of the guest stopped.
	envdPausedMark = "paused"
	// pausePoll is how often stopping processes are checked.
	pausePoll = 5 * time.Millisecond
	// envdPauseTimeout bounds how long an envd guest's init waits for its
	// processes to stop before it continues them again.
	envdPauseTimeout = 10 * time.Second
)

// Pause stops every process of running guest id. On error the guest runs
// again (or is gone, for Destroy).
func (d *Driver) Pause(ctx context.Context, id string) error {
	d.mu.Lock()
	g, ok := d.vms[id]
	if !ok || !g.running() || g.paused {
		d.mu.Unlock()
		return fmt.Errorf("guest %q: %w", id, vm.ErrNotRunning)
	}
	// Marked first, so nothing new starts in the guest while it stops.
	g.paused = true
	d.mu.Unlock()
	var err error
	if g.envd {
		err = g.pauseEnvd(ctx)
	} else {
		err = g.stopGroup(ctx)
	}
	if err == nil {
		return nil
	}
	if continueErr := g.continueGuest(context.WithoutCancel(ctx)); continueErr != nil {
		err = errors.Join(err, continueErr)
	}
	d.mu.Lock()
	g.paused = false
	d.mu.Unlock()
	return fmt.Errorf("pause guest %q: %w", id, err)
}

// Resume continues every process of paused guest id.
func (d *Driver) Resume(ctx context.Context, id string) error {
	d.mu.Lock()
	g, ok := d.vms[id]
	if !ok || !g.running() || !g.paused {
		d.mu.Unlock()
		return fmt.Errorf("guest %q: %w", id, vm.ErrNotPaused)
	}
	d.mu.Unlock()
	if err := g.continueGuest(ctx); err != nil {
		return fmt.Errorf("resume guest %q: %w", id, err)
	}
	d.mu.Lock()
	g.paused = false
	d.mu.Unlock()
	return nil
}

// continueGuest continues every process of the guest and, for an envd
// guest, waits until its init confirms it.
func (g *guest) continueGuest(ctx context.Context) error {
	if !g.envd {
		return syscall.Kill(-g.pgid(), syscall.SIGCONT)
	}
	if _, err := g.lifeline.Write([]byte{envdResume}); err != nil {
		return err
	}
	return g.waitPausedMark(ctx, false)
}

// pauseEnvd asks an envd guest's init (PID 1 of its namespace, which sees
// exactly the guest's processes) to stop the guest, and waits for its mark.
func (g *guest) pauseEnvd(ctx context.Context) error {
	if _, err := g.lifeline.Write([]byte{envdPause}); err != nil {
		return err
	}
	return g.waitPausedMark(ctx, true)
}

// waitPausedMark waits until the guest's paused mark exists (paused) or is
// gone (!paused).
func (g *guest) waitPausedMark(ctx context.Context, paused bool) error {
	mark := filepath.Join(g.dir, envdPausedMark)
	for {
		_, err := os.Lstat(mark)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if (err == nil) == paused {
			return nil
		}
		if !g.running() {
			return errors.New("envd guest exited")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pausePoll):
		}
	}
}

// stopGroup stops a strict guest's process group, again until every member
// is stopped (a member may fork while the first signal is delivered).
func (g *guest) stopGroup(ctx context.Context) error {
	pgid := g.pgid()
	for {
		if err := syscall.Kill(-pgid, syscall.SIGSTOP); err != nil {
			return err
		}
		stopped, err := procsStopped(func(_ int, stat procStat) bool { return stat.pgrp == pgid })
		if err != nil || stopped {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pausePoll):
		}
	}
}

// procsStopped reports whether every thread of every process in /proc that
// member selects (by PID and stat) is stopped or dead.
func procsStopped(member func(int, procStat) bool) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue // exited
		}
		stat, ok := statFields(string(raw))
		if !ok || !member(pid, stat) {
			continue
		}
		tasks, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "task"))
		if err != nil {
			continue
		}
		for _, task := range tasks {
			raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "task", task.Name(), "stat"))
			if err != nil {
				continue
			}
			if stat, ok := statFields(string(raw)); ok && !stoppedState(stat.state) {
				return false, nil
			}
		}
	}
	return true, nil
}

// stoppedState reports whether a /proc state letter runs no code.
func stoppedState(state byte) bool {
	switch state {
	case 'T', 't', 'Z', 'X':
		return true
	}
	return false
}

// pauseNamespace runs in an envd guest's init: it stops every other process
// of the PID namespace, then creates the paused mark in the guest directory.
// If they do not all stop in time it continues them again.
func pauseNamespace(dirFD int) error {
	deadline := time.Now().Add(envdPauseTimeout)
	for {
		_ = syscall.Kill(-1, syscall.SIGSTOP)
		stopped, err := procsStopped(func(pid int, _ procStat) bool { return pid != 1 })
		if err == nil && stopped {
			break
		}
		if err == nil && time.Now().After(deadline) {
			err = errors.New("guest processes did not stop")
		}
		if err != nil {
			_ = syscall.Kill(-1, syscall.SIGCONT)
			return err
		}
		time.Sleep(pausePoll)
	}
	fd, err := unix.Openat(dirFD, envdPausedMark, unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		_ = syscall.Kill(-1, syscall.SIGCONT)
		return err
	}
	return unix.Close(fd)
}

// resumeNamespace runs in an envd guest's init: it continues every other
// process of the PID namespace, then removes the paused mark.
func resumeNamespace(dirFD int) error {
	_ = syscall.Kill(-1, syscall.SIGCONT)
	if err := unix.Unlinkat(dirFD, envdPausedMark, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}
