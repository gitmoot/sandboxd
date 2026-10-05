//go:build sandboxd_devdriver && linux

package devvm

import (
	"context"
	"fmt"

	"github.com/gitmoot/sandboxd/internal/vm"
)

var _ vm.ConsoleReader = (*Driver)(nil)

// Console returns an envd guest's console output: envd's structured logs and
// its helper's stderr. A strict guest has no console.
func (d *Driver) Console(_ context.Context, id string) ([]vm.ConsoleLine, error) {
	g, err := d.running(id)
	if err != nil {
		return nil, err
	}
	if g.console == nil {
		return nil, fmt.Errorf("guest %q: %w", id, vm.ErrNoConsole)
	}
	return g.console.Lines(), nil
}
