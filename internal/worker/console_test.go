package worker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// consoleDriver keeps console lines for the VMs in lines only.
type consoleDriver struct {
	*fakeDriver
	lines map[string][]vm.ConsoleLine
}

func (d consoleDriver) Console(_ context.Context, id string) ([]vm.ConsoleLine, error) {
	lines, ok := d.lines[id]
	if !ok {
		return nil, fmt.Errorf("vm %s: %w", id, vm.ErrNoConsole)
	}
	return lines, nil
}

func TestConsoleRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 5, 9, 0, 0, 123456789, time.UTC)
	want := []vm.ConsoleLine{{Time: at, Text: `{"level":"info","message":"<envd> & up"}`}, {Time: at.Add(time.Millisecond), Text: "plain"}}
	driver := consoleDriver{fakeDriver: newFake(), lines: map[string][]vm.ConsoleLine{vmA: want, vmB: nil}}
	_, ts := serve(t, driver)
	client := enrolled(t, ts.URL, 1)
	ctx := context.Background()
	got, err := client.Console(ctx, vmA)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("console = %+v, %v", got, err)
	}
	if got, err := client.Console(ctx, vmB); err != nil || len(got) != 0 {
		t.Fatalf("empty console = %+v, %v", got, err)
	}
	if _, err := client.Console(ctx, "sandboxd-00000000000000000000000000000000"); !errors.Is(err, vm.ErrNoConsole) {
		t.Fatalf("console of a VM without one: %v", err)
	}
	if _, err := client.Console(ctx, "../etc"); err == nil {
		t.Fatal("console of an invalid VM ID")
	}
	// A stale lease is refused like every other leased call.
	if _, err := enrolled(t, ts.URL, 2).Console(ctx, vmA); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Console(ctx, vmA); !errors.Is(err, ErrStaleLease) {
		t.Fatalf("console under a stale lease: %v", err)
	}
}

func TestConsoleWithoutReader(t *testing.T) {
	_, ts := serve(t, newFake())
	if _, err := enrolled(t, ts.URL, 1).Console(context.Background(), vmA); !errors.Is(err, vm.ErrNoConsole) {
		t.Fatalf("remote console without a reader: %v", err)
	}
	if _, err := Local(newFake(), testDecl()).Console(context.Background(), vmA); !errors.Is(err, vm.ErrNoConsole) {
		t.Fatalf("local console without a reader: %v", err)
	}
	lines := []vm.ConsoleLine{{Time: time.Unix(1, 0).UTC(), Text: "x"}}
	got, err := Local(consoleDriver{fakeDriver: newFake(), lines: map[string][]vm.ConsoleLine{vmA: lines}}, testDecl()).Console(context.Background(), vmA)
	if err != nil || !reflect.DeepEqual(got, lines) {
		t.Fatalf("local console = %+v, %v", got, err)
	}
}
