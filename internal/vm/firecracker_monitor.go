//go:build linux

package vm

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// fcFirewallFailures is how many consecutive checks may fail to complete
// (an nft run that errs or times out) before the firewall counts as lost.
// A check that observes the table missing or changed is a loss at once.
const fcFirewallFailures = 2

// fcFirewallMonitor re-checks the host table once per interval for the whole
// driver, while anything watches it: running commands and open envd streams.
// On a loss it destroys every watched VM, then notifies each watcher.
type fcFirewallMonitor struct {
	mu       sync.Mutex
	watchers map[*fcWatcher]struct{}
	running  bool
	// okArmed and okAt record the armed table the last successful check
	// confirmed, and when; okArmed is "" after a failed check.
	okArmed string
	okAt    time.Time
}

type fcWatcher struct {
	id   string
	lost func(error)
	// done is closed once lost has run for a watcher the monitor took.
	done chan struct{}
}

func (m *fcFirewallMonitor) confirmed(armed string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.okArmed, m.okAt = armed, time.Now()
}

func (m *fcFirewallMonitor) fresh(armed string, every time.Duration) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.okArmed == armed && time.Since(m.okAt) < every
}

// watchFirewall subscribes VM id to the monitor, starting it if idle. lost
// runs at most once, after the VM was destroyed for a firewall loss. The
// returned function unsubscribes; if the loss is already being handled it
// waits until lost has run, so the caller then observes it.
func (d *FirecrackerDriver) watchFirewall(id string, lost func(error)) func() {
	m := &d.firewall
	w := &fcWatcher{id: id, lost: lost, done: make(chan struct{})}
	m.mu.Lock()
	if m.watchers == nil {
		m.watchers = map[*fcWatcher]struct{}{}
	}
	m.watchers[w] = struct{}{}
	start := !m.running
	m.running = true
	m.mu.Unlock()
	if start {
		go d.monitorFirewall()
	}
	return func() {
		m.mu.Lock()
		_, mine := m.watchers[w]
		delete(m.watchers, w)
		m.mu.Unlock()
		if !mine {
			<-w.done
		}
	}
}

// monitorFirewall runs while anything watches the firewall.
func (d *FirecrackerDriver) monitorFirewall() {
	m := &d.firewall
	ticker := time.NewTicker(d.firewallEvery)
	defer ticker.Stop()
	failures := 0
	for range ticker.C {
		m.mu.Lock()
		if len(m.watchers) == 0 {
			m.running = false
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := d.Ready(ctx)
		cancel()
		if err == nil {
			failures = 0
			continue
		}
		failures++
		if !errors.Is(err, errFirewallLost) && failures < fcFirewallFailures {
			log.Printf("firecracker: host firewall check failed (%d of %d tolerated): %v", failures, fcFirewallFailures-1, err)
			continue
		}
		failures = 0
		d.firewallLost(err)
	}
}

// firewallLost destroys every watched VM, then tells each watcher.
func (d *FirecrackerDriver) firewallLost(cause error) {
	m := &d.firewall
	m.mu.Lock()
	taken := make([]*fcWatcher, 0, len(m.watchers))
	for w := range m.watchers {
		taken = append(taken, w)
	}
	clear(m.watchers)
	m.mu.Unlock()
	destroyed := map[string]error{}
	for _, w := range taken {
		if _, done := destroyed[w.id]; done {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		destroyed[w.id] = d.Destroy(ctx, w.id)
		cancel()
		log.Printf("firecracker: destroyed %s after losing the host firewall: %v", w.id, cause)
	}
	for _, w := range taken {
		err := cause
		if destroyErr := destroyed[w.id]; destroyErr != nil {
			err = errors.Join(cause, fmt.Errorf("destroy %s: %w", w.id, destroyErr))
		}
		w.lost(err)
		close(w.done)
	}
}
