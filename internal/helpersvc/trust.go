package helpersvc

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// trusted refuses path unless it is itself (not through a symlink) a
// directory or regular file, as asked, owned by root and writable by nobody
// else. ACLs are not inspected.
func (h *Host) trusted(path string, dir bool) error {
	info, err := h.Lstat(path)
	if err != nil {
		return err
	}
	if dir && !info.IsDir() || !dir && !info.Mode().IsRegular() {
		kind := "regular file"
		if dir {
			kind = "directory"
		}
		return fmt.Errorf("%s must be a %s, not a symlink or anything else", path, kind)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != h.RootUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be owned by root and not writable by group or others", path)
	}
	return nil
}

// trustedTree refuses dir unless it and every directory above it up to
// TrustRoot are trusted: otherwise someone could rename a directory after
// the check and swap what root installs or runs.
func (h *Host) trustedTree(dir string) error {
	for d := dir; ; d = filepath.Dir(d) {
		if err := h.trusted(d, true); err != nil {
			return err
		}
		if d == h.TrustRoot {
			return nil
		}
		if filepath.Dir(d) == d {
			return fmt.Errorf("%s is outside %s", dir, h.TrustRoot)
		}
	}
}

// ensureTrustedDir creates a missing dir as root 0755, then requires the
// whole tree to be trusted.
func (h *Host) ensureTrustedDir(dir string) error {
	if _, err := h.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			return err
		}
		if err := h.Chown(dir); err != nil {
			return err
		}
	}
	return h.trustedTree(dir)
}

// writeFile atomically replaces path with data, owned by root with mode.
func (h *Host) writeFile(path string, data []byte, mode fs.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		if err = f.Chmod(mode); err == nil {
			err = f.Sync()
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = h.Chown(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
