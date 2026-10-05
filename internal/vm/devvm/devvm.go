//go:build sandboxd_devdriver && linux

// Package devvm is a CI-only vm.Driver that runs each "VM" as a group of
// plain local processes rooted in a per-sandbox temporary directory.
//
// It is NOT an isolation boundary. Guest commands run as the invoking host
// user, see the host filesystem and network, and are only steered into the
// sandbox directory: the guest home /home/user maps to <state>/<id>/home/user
// for working directories, uploads, and literal "/home/user" path words in
// command arguments and environment values. It exists so the control plane and
// the guest data plane can run under conformance suites on machines without
// Apple container or KVM.
//
// The package builds only with the sandboxd_devdriver tag, which no production
// binary uses; cmd/sandboxd has a test proving it never links this package.
package devvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/vm"
)

const (
	// GuestHome is the only guest directory the dev driver maps.
	GuestHome    = "/home/user"
	maxCopyBytes = 512 << 20
	// userHZ is the fixed /proc clock-tick unit on Linux (USER_HZ).
	userHZ      = 100
	guestPath   = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	cpuInterval = 200 * time.Millisecond
	// outputDrain bounds how long Run waits for output from background
	// processes that inherited the command's pipes after it exited.
	outputDrain = time.Second
)

var (
	envName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9]*$`)
	idChars = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
)

// Driver keeps every guest in memory; a restarted process starts empty and
// refuses a state directory that still holds guests from an earlier run.
type Driver struct {
	root  string
	sleep string
	envd  Envd
	mu    sync.Mutex
	vms   map[string]*guest
}

type guest struct {
	network   string
	memoryMiB int
	dir       string
	home      string
	holder    *exec.Cmd
	exited    chan struct{}
	// envd marks an envd guest: holder is its root helper, and closing
	// lifeline ends it (see envd.go).
	envd     bool
	lifeline io.Closer
}

var (
	_ vm.Driver        = (*Driver)(nil)
	_ vm.ResourceMeter = (*Driver)(nil)
	_ vm.EnvdDialer    = (*Driver)(nil)
)

// New uses root, which must be absent or empty, as the parent of all guest
// directories. envd configures envd guests; its zero value refuses them.
func New(root string, envd Envd) (*Driver, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("dev driver state directory must be an absolute clean path")
	}
	if err := envd.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		return nil, fmt.Errorf("dev driver state directory %s is not empty; remove stale guests first", root)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		return nil, fmt.Errorf("dev driver needs sleep(1) for guest holder processes: %w", err)
	}
	return &Driver{root: root, sleep: sleep, envd: envd, vms: map[string]*guest{}}, nil
}

// Create starts a holder process whose process group is the guest: every
// command joins it, and Destroy kills the whole group.
func (d *Driver) Create(ctx context.Context, spec vm.Spec) (vm.Instance, error) {
	if !idChars.MatchString(spec.ID) {
		return vm.Instance{}, fmt.Errorf("invalid guest ID %q", spec.ID)
	}
	if spec.Image == "" || spec.Network == "" || spec.CPUs < 1 || spec.MemoryMiB < 1 {
		return vm.Instance{}, errors.New("guest image, network, CPU and memory must be set")
	}
	if err := ctx.Err(); err != nil {
		return vm.Instance{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.vms[spec.ID]; exists {
		return vm.Instance{}, fmt.Errorf("guest %q already exists", spec.ID)
	}
	for _, other := range d.vms {
		if other.network == spec.Network && other.running() {
			return vm.Instance{}, fmt.Errorf("guest network %q is in use", spec.Network)
		}
	}
	dir := filepath.Join(d.root, spec.ID)
	home := filepath.Join(dir, "home", "user")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return vm.Instance{}, err
	}
	if spec.Envd {
		g, err := d.createEnvd(spec, dir)
		if err != nil {
			return vm.Instance{}, errors.Join(err, os.RemoveAll(dir))
		}
		d.vms[spec.ID] = g
		return vm.Instance{ID: spec.ID, Running: true, Network: spec.Network}, nil
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return vm.Instance{}, errors.Join(err, os.RemoveAll(dir))
	}
	holder := exec.Command(d.sleep, "infinity")
	holder.Dir = home
	holder.Env = baseEnv(home)
	holder.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := holder.Start(); err != nil {
		return vm.Instance{}, errors.Join(err, os.RemoveAll(dir))
	}
	g := &guest{network: spec.Network, memoryMiB: spec.MemoryMiB, dir: dir, home: home, holder: holder, exited: make(chan struct{})}
	go func() {
		_ = holder.Wait()
		close(g.exited)
	}()
	d.vms[spec.ID] = g
	return vm.Instance{ID: spec.ID, Running: true, Network: spec.Network}, nil
}

func (g *guest) running() bool {
	select {
	case <-g.exited:
		return false
	default:
		return true
	}
}

func (g *guest) pgid() int { return g.holder.Process.Pid }

// List is complete by construction: the driver owns every guest it reports.
func (d *Driver) List(context.Context) ([]vm.Instance, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	instances := make([]vm.Instance, 0, len(d.vms))
	for id, g := range d.vms {
		instances = append(instances, vm.Instance{ID: id, Running: g.running(), Network: g.network})
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ID < instances[j].ID })
	return instances, nil
}

// runningStrict is running for a strict guest; envd guests are reached only
// through DialEnvd.
func (d *Driver) runningStrict(id string) (*guest, error) {
	g, err := d.running(id)
	if err == nil && g.envd {
		return nil, fmt.Errorf("guest %q runs envd; it has no strict guest API", id)
	}
	return g, err
}

func (d *Driver) running(id string) (*guest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	g, ok := d.vms[id]
	if !ok || !g.running() {
		return nil, fmt.Errorf("guest %q is not running", id)
	}
	return g, nil
}

// hostPath maps a clean absolute guest path at or below GuestHome.
func (g *guest) hostPath(guestPath string) (string, error) {
	if guestPath == GuestHome {
		return g.home, nil
	}
	if path.Clean(guestPath) != guestPath || !strings.HasPrefix(guestPath, GuestHome+"/") || strings.ContainsAny(guestPath, "\x00\r\n") {
		return "", fmt.Errorf("dev driver maps only clean paths under %s, not %q", GuestHome, guestPath)
	}
	return filepath.Join(g.home, strings.TrimPrefix(guestPath, GuestHome)), nil
}

// CopyIn writes a regular host file into the guest, creating missing parents
// (mode 0700) and truncating an existing file, as the Apple driver does.
func (d *Driver) CopyIn(ctx context.Context, id, source, destination string) error {
	g, err := d.runningStrict(id)
	if err != nil {
		return err
	}
	target, err := g.hostPath(destination)
	if err != nil || target == g.home {
		return fmt.Errorf("unsafe guest destination %q", destination)
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || strings.ContainsRune(source, 0) {
		return errors.New("source must be an absolute clean host file path")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCopyBytes {
		return fmt.Errorf("copy source must be a regular file no larger than %d bytes", maxCopyBytes)
	}
	if err := noSymlinks(g.home, target); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(in, maxCopyBytes+1))
	closeErr := out.Close()
	if err := errors.Join(copyErr, closeErr, ctx.Err()); err != nil {
		return err
	}
	if n > maxCopyBytes {
		return fmt.Errorf("copy source exceeds %d bytes", maxCopyBytes)
	}
	return nil
}

// noSymlinks refuses a target whose existing components below home include a
// symlink, so an upload cannot be redirected outside the guest directory.
func noSymlinks(home, target string) error {
	rel, err := filepath.Rel(home, target)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("guest destination %q escapes the guest home", target)
	}
	current := home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("guest destination %q passes through a symlink", target)
		}
	}
	return nil
}

// Run starts the command in the guest's process group. Cancellation kills the
// command; Destroy kills everything the guest started.
func (d *Driver) Run(ctx context.Context, id string, command vm.Command, stdout, stderr io.Writer) (int, error) {
	g, err := d.runningStrict(id)
	if err != nil {
		return 0, err
	}
	if len(command.Args) == 0 || command.Args[0] == "" {
		return 0, errors.New("empty guest command")
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, 0) {
			return 0, errors.New("NUL in guest command")
		}
	}
	if command.User != "" && command.User != "user" && command.User != "1000" && command.User != "1000:1000" {
		return 0, fmt.Errorf("guest user %q is not permitted", command.User)
	}
	dir := g.home
	if command.Dir != "" {
		if dir, err = g.hostPath(command.Dir); err != nil {
			return 0, err
		}
	}
	env := baseEnv(g.home)
	keys := make([]string, 0, len(command.Env))
	for key, value := range command.Env {
		if !envName.MatchString(key) || strings.ContainsRune(value, 0) {
			return 0, fmt.Errorf("unsafe guest environment variable %q", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = setEnv(env, key, mapGuestHome(command.Env[key], g.home))
	}
	args := make([]string, len(command.Args))
	for i, arg := range command.Args {
		args[i] = mapGuestHome(arg, g.home)
	}
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Dir, c.Env, c.Stdout, c.Stderr = dir, env, stdout, stderr
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: g.pgid(), Pdeathsig: syscall.SIGKILL}
	c.WaitDelay = outputDrain
	if err := c.Start(); err != nil {
		return 0, err
	}
	if command.OnStart != nil {
		command.OnStart(c.Process.Pid)
	}
	err = c.Wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, ctxErr
	}
	if !g.running() {
		return 0, fmt.Errorf("guest %q stopped during execution", id)
	}
	if c.ProcessState == nil {
		return 0, err
	}
	if status, ok := c.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal()), nil
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return 0, err
		}
	}
	return c.ProcessState.ExitCode(), nil
}

// Usage samples the guest process group's /proc counters twice. Memory limit
// is the configured guest size; the dev driver does not enforce it.
func (d *Driver) Usage(ctx context.Context, id string) (vm.Usage, error) {
	g, err := d.running(id)
	if err != nil {
		return vm.Usage{}, err
	}
	sample := func() (groupSample, error) { return sampleGroup(g.pgid()) }
	if g.envd {
		sample = func() (groupSample, error) { return sampleTree(g.holder.Process.Pid) }
	}
	first, err := sample()
	if err != nil {
		return vm.Usage{}, err
	}
	started := time.Now()
	select {
	case <-ctx.Done():
		return vm.Usage{}, ctx.Err()
	case <-time.After(cpuInterval):
	}
	second, err := sample()
	if err != nil {
		return vm.Usage{}, err
	}
	if !g.running() || second.rssBytes == 0 {
		return vm.Usage{}, fmt.Errorf("guest %q stopped while sampling", id)
	}
	var ticks uint64
	if second.ticks > first.ticks {
		ticks = second.ticks - first.ticks
	}
	elapsed := time.Since(started).Seconds()
	var diskUsed uint64
	if g.envd {
		diskUsed = readableBytes(g.home, filepath.Join(g.dir, "tmp"), filepath.Join(g.dir, "root"))
	} else if diskUsed, err = allocatedBytes(g.home); err != nil {
		return vm.Usage{}, err
	}
	var volume syscall.Statfs_t
	if err := syscall.Statfs(g.home, &volume); err != nil {
		return vm.Usage{}, err
	}
	return vm.Usage{
		CPUUsedPct:       float64(ticks) / userHZ / elapsed * 100,
		MemoryUsedBytes:  second.rssBytes,
		MemoryLimitBytes: uint64(g.memoryMiB) << 20,
		Detailed:         true,
		MemoryCacheBytes: second.fileBytes,
		DiskUsedBytes:    diskUsed,
		DiskTotalBytes:   volume.Blocks * uint64(volume.Bsize),
	}, nil
}

// allocatedBytes sums the allocated blocks of everything under root without
// following symlinks. Entries removed during the walk are skipped.
func allocatedBytes(root string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		info, err := entry.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Blocks > 0 {
			total += uint64(stat.Blocks) * 512
		}
		return nil
	})
	return total, err
}

type groupSample struct {
	ticks    uint64
	rssBytes uint64
	// fileBytes is resident file-backed memory (statm "shared"), the guest's
	// share of the page cache.
	fileBytes uint64
}

// sampleGroup sums utime+stime, RSS and resident file-backed pages of live
// processes in process group pgid. Processes that exit between listing and
// reading are skipped.
func sampleGroup(pgid int) (groupSample, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return groupSample{}, err
	}
	page := uint64(os.Getpagesize())
	var sample groupSample
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		fields, ok := statFields(string(raw))
		if !ok || fields.pgrp != pgid {
			continue
		}
		sample.ticks += fields.utime + fields.stime
		sample.rssBytes += fields.rssPages * page
		if statm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "statm")); err == nil {
			if values := strings.Fields(string(statm)); len(values) >= 3 {
				if shared, err := strconv.ParseUint(values[2], 10, 64); err == nil {
					sample.fileBytes += shared * page
				}
			}
		}
	}
	return sample, nil
}

type procStat struct {
	ppid, pgrp             int
	utime, stime, rssPages uint64
}

// statFields parses /proc/<pid>/stat after the parenthesized command name,
// which may itself contain spaces and parentheses.
func statFields(raw string) (procStat, bool) {
	end := strings.LastIndexByte(raw, ')')
	if end < 0 {
		return procStat{}, false
	}
	// Fields after ")" start at field 3 (state); pgrp is field 5, utime 14,
	// stime 15, rss 24.
	fields := strings.Fields(raw[end+1:])
	if len(fields) < 22 {
		return procStat{}, false
	}
	ppid, err0 := strconv.Atoi(fields[1])
	pgrp, err1 := strconv.Atoi(fields[2])
	utime, err2 := strconv.ParseUint(fields[11], 10, 64)
	stime, err3 := strconv.ParseUint(fields[12], 10, 64)
	rss, err4 := strconv.ParseInt(fields[21], 10, 64)
	if err := errors.Join(err0, err1, err2, err3, err4); err != nil || rss < 0 {
		return procStat{}, false
	}
	return procStat{ppid: ppid, pgrp: pgrp, utime: utime, stime: stime, rssPages: uint64(rss)}, true
}

// Destroy kills the guest's process group, waits until no member remains, and
// removes its directory. An unknown ID is already absent.
func (d *Driver) Destroy(ctx context.Context, id string) error {
	d.mu.Lock()
	g, ok := d.vms[id]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	if g.envd {
		if err := g.destroyEnvd(ctx); err != nil {
			return fmt.Errorf("guest %q: %w", id, err)
		}
		// The root helper removed everything it created; what remains
		// belongs to the driver.
		if err := os.Remove(g.dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove guest %q directory: %w", id, err)
		}
		d.mu.Lock()
		delete(d.vms, id)
		d.mu.Unlock()
		return nil
	}
	pgid := g.pgid()
	for {
		err := syscall.Kill(-pgid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			break
		}
		if err != nil {
			return fmt.Errorf("kill guest %q: %w", id, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("guest %q processes remain: %w", id, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-g.exited:
	case <-ctx.Done():
		return fmt.Errorf("guest %q holder not reaped: %w", id, ctx.Err())
	}
	if err := removeTree(g.dir); err != nil {
		return fmt.Errorf("remove guest %q directory: %w", id, err)
	}
	d.mu.Lock()
	delete(d.vms, id)
	d.mu.Unlock()
	return nil
}

// removeTree also removes directories a guest made unwritable.
func removeTree(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	_ = filepath.WalkDir(dir, func(p string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}

// Close destroys every guest.
func (d *Driver) Close(ctx context.Context) error {
	d.mu.Lock()
	ids := make([]string, 0, len(d.vms))
	for id := range d.vms {
		ids = append(ids, id)
	}
	d.mu.Unlock()
	var errs []error
	for _, id := range ids {
		errs = append(errs, d.Destroy(ctx, id))
	}
	return errors.Join(errs...)
}

func baseEnv(home string) []string {
	return []string{"HOME=" + home, "LANG=C.UTF-8", "LOGNAME=user", "PATH=" + guestPath, "USER=user"}
}

func setEnv(env []string, key, value string) []string {
	for i, entry := range env {
		if strings.HasPrefix(entry, key+"=") {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}

// mapGuestHome rewrites each "/home/user" path word to home. A match must not
// continue a longer name ("/home/username", "/x/home/user").
func mapGuestHome(value, home string) string {
	var out strings.Builder
	start := 0
	for {
		i := strings.Index(value[start:], GuestHome)
		if i < 0 {
			out.WriteString(value[start:])
			return out.String()
		}
		i += start
		end := i + len(GuestHome)
		startsWord := i == 0 || !pathChar(value[i-1])
		endsWord := end == len(value) || value[end] == '/' || !pathChar(value[end])
		out.WriteString(value[start:i])
		if startsWord && endsWord {
			out.WriteString(home)
		} else {
			out.WriteString(GuestHome)
		}
		start = end
	}
}

func pathChar(c byte) bool {
	return c == '/' || c == '.' || c == '-' || c == '_' ||
		c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
