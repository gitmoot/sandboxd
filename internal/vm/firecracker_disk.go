//go:build linux

package vm

import (
	"fmt"
	"sync"
)

// fcWrite is a snapshot write under Root, a pause's or a template build's:
// up to need bytes written as owner into files. Until it is done it holds
// what it has not written yet above the disk floor, so writers admitted
// together never promise the same space, and what it has written, already
// gone from the free space, is not charged twice.
type fcWrite struct {
	what  string
	need  uint64
	owner int
	files []fcWrittenFile
}

// fcWrittenFile is file name in an open directory dir.
type fcWrittenFile struct {
	dir  int
	name string
}

// pending is what write w has yet to write.
func (d *FirecrackerDriver) pending(w *fcWrite) uint64 {
	var written uint64
	for _, file := range w.files {
		written += d.host.WrittenBytes(file.dir, file.name, w.owner)
	}
	return w.need - min(w.need, written)
}

// pendingLocked is what every admitted write has yet to write. writesMu
// must be held.
func (d *FirecrackerDriver) pendingLocked() uint64 {
	var pending uint64
	for w := range d.writes {
		pending += d.pending(w)
	}
	return pending
}

// admitWrite admits w if the free space under Root keeps the disk floor and
// what every admitted write has yet to write, plus all of w. release ends
// it once its files are complete or gone; their directories must stay open
// until then.
func (d *FirecrackerDriver) admitWrite(w *fcWrite) (release func(), err error) {
	d.writesMu.Lock()
	defer d.writesMu.Unlock()
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return nil, err
	}
	pending := d.pendingLocked()
	if free < uint64(d.cfg.DiskFloorMiB)<<20+pending+w.need {
		return nil, fmt.Errorf("%w: %d MiB free, %d MiB floor and %d MiB of snapshot writes in progress plus %d MiB %s needed",
			ErrDiskFloor, free>>20, d.cfg.DiskFloorMiB, pending>>20, w.need>>20, w.what)
	}
	if d.writes == nil {
		d.writes = map[*fcWrite]struct{}{}
	}
	d.writes[w] = struct{}{}
	return sync.OnceFunc(func() {
		d.writesMu.Lock()
		delete(d.writes, w)
		d.writesMu.Unlock()
	}), nil
}

// rootFree is the free space under Root less what admitted snapshot writes
// have yet to write.
func (d *FirecrackerDriver) rootFree() (uint64, error) {
	d.writesMu.Lock()
	defer d.writesMu.Unlock()
	free, err := d.host.FreeBytes(d.cfg.Root)
	if err != nil {
		return 0, err
	}
	return free - min(free, d.pendingLocked()), nil
}
