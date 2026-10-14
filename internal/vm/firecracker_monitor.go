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

// fcEventsStable is how long the event subscription must have run for its
// end to count as a fresh failure rather than the next one in a row.
const fcEventsStable = 10 * time.Second

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
		// No volume flush: a guest behind a lost firewall stops at once.
		destroyed[w.id] = d.destroy(ctx, w.id, false)
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

// FirewallLost reports the first firewall loss found by the event path
// (WatchFirewallEvents): the daemon stops guest work on it at once, as it
// does when its own one-second check fails.
func (d *FirecrackerDriver) FirewallLost() <-chan error { return d.lost }

// reportLost destroys every watched VM, then tells the daemon, once.
func (d *FirecrackerDriver) reportLost(cause error) {
	d.firewallLost(cause)
	d.lostOnce.Do(func() { d.lost <- cause })
}

// WatchFirewallEvents re-checks the host table the moment the host's
// ruleset changes, instead of up to a poll interval later: it subscribes to
// nftables change events in the host namespace and runs one check per burst
// of events. It runs until ctx ends; start it after Arm. The polls (the
// command monitor, and the daemon's own one-second check) stay as backups,
// for events missed or a subscription that is down.
//
// A subscription that stops is restarted, and counts as a failed check
// under the same tolerance as the poll: fcFirewallFailures failures in a
// row, each within fcEventsStable of the last start, are reported as a
// loss. The table cannot be watched, so guests must not keep running.
func (d *FirecrackerDriver) WatchFirewallEvents(ctx context.Context) {
	check := make(chan struct{}, 1)
	trigger := func() {
		select {
		case check <- struct{}{}:
		default: // a check is already due; it reads the table after this event
		}
	}
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		for {
			select {
			case <-ctx.Done():
				return
			case <-check:
			}
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := d.Ready(checkCtx)
			cancel()
			switch {
			case err == nil, ctx.Err() != nil:
			case errors.Is(err, errFirewallLost):
				log.Printf("firecracker: host firewall changed (nftables event): %v", err)
				d.reportLost(err)
				return
			default:
				// An nft run that failed; the polls apply their own tolerance.
				log.Printf("firecracker: host firewall check after nftables event failed: %v", err)
			}
		}
	}()
	defer func() { <-checked }()
	failures := 0
	for ctx.Err() == nil {
		started := time.Now()
		// Check once per subscription start: events from before it are lost.
		trigger()
		err := d.host.MonitorRuleset(ctx, trigger)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) >= fcEventsStable {
			failures = 0
		}
		failures++
		if failures >= fcFirewallFailures {
			d.reportLost(fmt.Errorf("%w: firewall change events unavailable (%d failures in a row): %v", errFirewallLost, failures, err))
			return
		}
		log.Printf("firecracker: firewall event subscription stopped (%d of %d tolerated), restarting: %v", failures, fcFirewallFailures-1, err)
		trigger()
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.eventsRestart()):
		}
	}
}

// eventsRestart is the pause before a stopped subscription is restarted.
func (d *FirecrackerDriver) eventsRestart() time.Duration {
	return min(d.firewallEvery, time.Second)
}
