package control

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

func slotConfig(maxVMs int, slots ...string) Config {
	return Config{APIKey: "control-secret", TemplateID: "review-arm64", Image: "linux-arm64", Domain: "sandbox.example",
		WorkerID: "mac-local", CPUs: 2, MemoryMiB: 512, MaxVMs: maxVMs, MaxTTL: time.Hour, Slots: slots}
}

func openSlotService(t *testing.T, path string, driver *fakeDriver, cfg Config) *Service {
	t.Helper()
	s, err := Open(context.Background(), path, driver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestConcurrentGuestsEachCreateOnTheirOwnSlot(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	s := openSlotService(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, slotConfig(3, "slot-1", "slot-2", "slot-3"))
	var wg sync.WaitGroup
	codes := make(chan int, 5)
	for _, job := range []string{"a", "b", "c", "d", "e"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- request(t, s, http.MethodPost, "/sandboxes", createBody("job-"+job, 1)).Code
		}()
	}
	wg.Wait()
	close(codes)
	created := 0
	for code := range codes {
		if code == http.StatusCreated {
			created++
		}
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if created != 3 || len(driver.instances) != 3 {
		t.Fatalf("admitted %d guests (%d VMs) on 3 slots", created, len(driver.instances))
	}
	seen := make(map[string]bool)
	for id, instance := range driver.instances {
		row, err := s.ledger.Get(context.Background(), id)
		if err != nil || row.Slot == "" || instance.Network != row.Slot || seen[row.Slot] {
			t.Fatalf("guest %s created on %q, recorded slot %q (shared=%v): %v", id, instance.Network, row.Slot, seen[row.Slot], err)
		}
		seen[row.Slot] = true
	}
}

func TestSlotHeldByUnresolvedCreateIsNotReassigned(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance), createError: errors.New("response lost")}
	s := openSlotService(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, slotConfig(2, "slot-1", "slot-2"))
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-a", 1)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("ambiguous create: %d", got.Code)
	}
	var lost string
	driver.mu.Lock()
	for id := range driver.instances {
		lost = id
	}
	driver.createError = nil
	driver.destroyError = errors.New("worker unreachable")
	driver.mu.Unlock()
	// The lost guest cannot be proven gone: nobody may take any slot.
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-b", 1)); got.Code == http.StatusCreated {
		t.Fatal("admitted while an unknown guest's slot was unresolved")
	}
	if row, err := s.ledger.Get(context.Background(), lost); err != nil || row.State != "unknown" || row.Slot != "slot-1" {
		t.Fatalf("unresolved reservation released its slot: %+v %v", row, err)
	}
	driver.mu.Lock()
	driver.destroyError = nil
	driver.mu.Unlock()
	id, _ := createSandbox(t, s, "job-b")
	driver.mu.Lock()
	network := driver.instances[id].Network
	driver.mu.Unlock()
	if row, _ := s.ledger.Get(context.Background(), id); row.Slot != "slot-1" || network != "slot-1" {
		t.Fatalf("slot proved free was not reused: %+v on %q", row, network)
	}
}

func TestGuestObservedOffItsSlotIsReaped(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	s := openSlotService(t, filepath.Join(t.TempDir(), "ledger.sqlite"), driver, slotConfig(2, "slot-1", "slot-2"))
	id, token := createSandbox(t, s, "job-a")
	driver.mu.Lock()
	moved := driver.instances[id]
	moved.Network = "slot-2"
	driver.instances[id] = moved
	driver.mu.Unlock()
	createSandbox(t, s, "job-b")
	if s.Authorize(id, token) {
		t.Fatal("kept a guest attached to a slot it does not own")
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if _, alive := driver.instances[id]; alive {
		t.Fatal("guest off its slot was not destroyed")
	}
}

func TestSlotConfigurationBoundsCapacity(t *testing.T) {
	driver := &fakeDriver{instances: make(map[string]vm.Instance)}
	for _, cfg := range []Config{
		slotConfig(1),
		slotConfig(3, "slot-1", "slot-2"),
		slotConfig(2, "slot-1", "slot-1"),
		slotConfig(1, ""),
	} {
		if s, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.sqlite"), driver, cfg); err == nil {
			_ = s.Close()
			t.Fatalf("accepted slots %q with max VMs %d", cfg.Slots, cfg.MaxVMs)
		}
	}
}

// A ledger written before slots existed can hold a live guest whose network is
// unknown. It is kept, not guessed onto a slot, and blocks admission until it
// is proved gone.
func TestPreSlotLiveGuestBlocksAdmissionUntilGone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	const legacy = "sandboxd-00000000000000000000000000000002"
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`CREATE TABLE sandboxes (
		id TEXT PRIMARY KEY, token_hash BLOB NOT NULL, metadata TEXT NOT NULL,
		job_id TEXT NOT NULL, attempt INTEGER NOT NULL, generation INTEGER NOT NULL,
		fence TEXT NOT NULL, state TEXT NOT NULL,
		template_id TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '',
		worker_id TEXT NOT NULL DEFAULT '',
		started_ns INTEGER NOT NULL, ends_ns INTEGER NOT NULL
	)`)
	if err == nil {
		_, err = old.Exec(`INSERT INTO sandboxes VALUES (?,x'00','{}','legacy-job',1,1,'','running','review-arm64','linux-arm64','mac-local',?,?)`,
			legacy, time.Now().UnixNano(), time.Now().Add(time.Hour).UnixNano())
	}
	if closeErr := old.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	driver := &fakeDriver{instances: map[string]vm.Instance{legacy: {ID: legacy, Running: true, Network: "sandboxd-internal"}}}
	s := openSlotService(t, path, driver, slotConfig(2, "slot-1", "slot-2"))
	if got := request(t, s, http.MethodPost, "/sandboxes", createBody("job-a", 1)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("admitted beside a live pre-slot guest: %d", got.Code)
	}
	driver.mu.Lock()
	_, alive := driver.instances[legacy]
	driver.instances[legacy] = vm.Instance{ID: legacy, Network: "sandboxd-internal"} // The legacy guest stops.
	driver.mu.Unlock()
	if !alive {
		t.Fatal("destroyed a live, current pre-slot guest")
	}
	id, _ := createSandbox(t, s, "job-a")
	if row, _ := s.ledger.Get(context.Background(), id); row.Slot != "slot-1" {
		t.Fatalf("legacy guest proved gone did not free admission: %+v", row)
	}
}
