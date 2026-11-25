//go:build linux

package vm

import (
	"fmt"
	"sync"
)

// fcSnapshotStateMiB is what a snapshot write takes beyond its memory file
// (and a build's home disk): the VM state file (vCPU and device state,
// kilobytes per vCPU) and the files' extent blocks.
const fcSnapshotStateMiB = 1

// fcWrite is a snapshot write under Root, a pause's or a template build's:
// at most need bytes written as owner into files, which only grow while the
// write can still write. Until it is done it holds what it has not written
// yet above the disk floor, so writers admitted together never promise the
// same space, and what it has written, already gone from the free space, is
// not charged twice.
//
// Accounting never errs toward overspending. Every writer's files are
// sampled first, the free space last. A writer that writes between the two
// samples has its new blocks both taken from the free space and still
// charged as unwritten: the space it can yet take is overestimated by them.
// Free space released between the samples (a discarded output, a deleted
// VM) only raises the free space read. So a write racing admission can make
// it refuse near the floor, never admit beyond it.
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

// headroom samples what every admitted write has yet to write, then the
// free space under Root (in that order: see fcWrite). writesMu must be held.
func (d *FirecrackerDriver) headroom() (free, pending uint64, err error) {
	for w := range d.writes {
		pending += d.pending(w)
	}
	free, err = d.host.FreeBytes(d.cfg.Root)
	return free, pending, err
}

// admitWrite admits w if the free space under Root keeps the disk floor and
// what every admitted write has yet to write, plus all of w. release ends
// it; the caller calls it only once nothing can write w's files any more
// (its VMM answered after the write, or is stopped), and keeps their
// directories open until then.
func (d *FirecrackerDriver) admitWrite(w *fcWrite) (release func(), err error) {
	d.writesMu.Lock()
	defer d.writesMu.Unlock()
	free, pending, err := d.headroom()
	if err != nil {
		return nil, err
	}
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
// have yet to write, sampled as admitWrite does.
func (d *FirecrackerDriver) rootFree() (uint64, error) {
	d.writesMu.Lock()
	defer d.writesMu.Unlock()
	free, pending, err := d.headroom()
	if err != nil {
		return 0, err
	}
	return free - min(free, pending), nil
}
