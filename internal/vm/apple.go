package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	appleNamePrefix       = "sandboxd-"
	appleOwnerLabel       = "gitmoot.sandboxd.owner=apple-v1"
	appleVolumeOwnerLabel = "gitmoot.sandboxd.volume=apple-v1"
	appleVolumeSize       = "10g"
	maxCopyBytes          = 512 << 20
)

var appleID = regexp.MustCompile(`^sandboxd-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
var envName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z_0-9]*$`)
var appleNetworkName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// AppleDriver uses Apple container 1.4.1's one-VM-per-container runtime.
// Each guest has a read-only root, a fixed-size private ext4 home volume,
// bounded tmpfs mounts, and a dedicated host-only network. No writable host
// paths are exposed to the guest.
type AppleDriver struct {
	cli     string
	images  map[string]struct{}
	network string
}

var _ Driver = (*AppleDriver)(nil)

// NewAppleDriver requires an absolute CLI path, an exact image allowlist, and
// a dedicated host-only network. It never falls back to the default NAT.
func NewAppleDriver(cliPath string, images []string, network string) (*AppleDriver, error) {
	if !filepath.IsAbs(cliPath) || filepath.Clean(cliPath) != cliPath || strings.ContainsRune(cliPath, 0) {
		return nil, fmt.Errorf("Apple container CLI path must be absolute and clean")
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("Apple container image allowlist must not be empty")
	}
	allowed := make(map[string]struct{}, len(images))
	for _, image := range images {
		if image == "" || image[0] == '-' || strings.IndexFunc(image, func(r rune) bool { return r <= ' ' || r == 127 }) >= 0 {
			return nil, fmt.Errorf("invalid Apple container image %q", image)
		}
		allowed[image] = struct{}{}
	}
	if !appleNetworkName.MatchString(network) || network == "default" {
		return nil, fmt.Errorf("invalid private Apple container network %q", network)
	}
	return &AppleDriver{cli: cliPath, images: allowed, network: network}, nil
}

func validAppleID(id string) error {
	if len(id) > 63 || !appleID.MatchString(id) {
		return fmt.Errorf("invalid sandboxd container ID %q", id)
	}
	return nil
}

func (d *AppleDriver) command(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, d.cli, args...)
	// Never inherit host secrets or CLI configuration from the worker's shell.
	// Apple's CLI needs the current user's HOME to locate its service socket.
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME")}
	return c
}

func (d *AppleDriver) output(ctx context.Context, args ...string) ([]byte, error) {
	c := d.command(ctx, args...)
	out, err := c.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("container %s: %w: %s", args[0], err, strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, fmt.Errorf("container %s: %w", args[0], err)
	}
	return out, nil
}

type appleContainer struct {
	Configuration struct {
		ID     string            `json:"id"`
		Labels map[string]string `json:"labels"`
	} `json:"configuration"`
	Status struct {
		State string `json:"state"`
	} `json:"status"`
}

// inventory always asks for stopped containers as well. The JSON structure
// follows ManagedContainer in Apple's 1.4.1 CLI, not its human-readable table.
func (d *AppleDriver) inventory(ctx context.Context) ([]appleContainer, error) {
	out, err := d.output(ctx, "list", "--all", "--format", "json")
	if err != nil {
		return nil, err
	}
	var items []appleContainer
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("incomplete Apple container inventory: %w", err)
	}
	if items == nil {
		return nil, fmt.Errorf("incomplete Apple container inventory: null result")
	}
	for _, item := range items {
		if item.Configuration.ID == "" || item.Status.State == "" {
			return nil, fmt.Errorf("incomplete Apple container inventory entry")
		}
	}
	return items, nil
}

func ownedApple(item appleContainer) bool {
	return strings.HasPrefix(item.Configuration.ID, appleNamePrefix) &&
		item.Configuration.Labels["gitmoot.sandboxd.owner"] == "apple-v1"
}

// lookup rejects a prefix collision without the ownership label; it must not
// treat such an existing container as absent or operate on it.
func (d *AppleDriver) lookup(ctx context.Context, id string) (appleContainer, bool, error) {
	if err := validAppleID(id); err != nil {
		return appleContainer{}, false, err
	}
	items, err := d.inventory(ctx)
	if err != nil {
		return appleContainer{}, false, err
	}
	for _, item := range items {
		if item.Configuration.ID == id {
			if !ownedApple(item) {
				return appleContainer{}, false, fmt.Errorf("container %q is not owned by sandboxd", id)
			}
			return item, true, nil
		}
	}
	return appleContainer{}, false, nil
}

type appleVolume struct {
	ID            string `json:"id"`
	Configuration struct {
		Labels map[string]string `json:"labels"`
	} `json:"configuration"`
}

// lookupVolume relies on complete volume inventory; a missing or malformed
// inventory is not proof that a job's writable disk was deleted.
func (d *AppleDriver) lookupVolume(ctx context.Context, id string) (bool, error) {
	if err := validAppleID(id); err != nil {
		return false, err
	}
	out, err := d.output(ctx, "volume", "list", "--format", "json")
	if err != nil {
		return false, err
	}
	var volumes []appleVolume
	if err := json.Unmarshal(out, &volumes); err != nil || volumes == nil {
		return false, fmt.Errorf("incomplete Apple volume inventory: %w", errors.Join(err, errors.New("no volume list")))
	}
	for _, volume := range volumes {
		if volume.ID == "" {
			return false, errors.New("incomplete Apple volume inventory entry")
		}
		if volume.ID == id {
			if volume.Configuration.Labels["gitmoot.sandboxd.volume"] != "apple-v1" {
				return false, fmt.Errorf("volume %q is not owned by sandboxd", id)
			}
			return true, nil
		}
	}
	return false, nil
}

type appleNetwork struct {
	ID            string `json:"id"`
	Configuration struct {
		Mode   string            `json:"mode"`
		Labels map[string]string `json:"labels"`
	} `json:"configuration"`
}

func (d *AppleDriver) checkNetwork(ctx context.Context) error {
	out, err := d.output(ctx, "network", "list", "--format", "json")
	if err != nil {
		return err
	}
	var networks []appleNetwork
	if err := json.Unmarshal(out, &networks); err != nil || networks == nil {
		return fmt.Errorf("incomplete Apple network inventory: %w", errors.Join(err, errors.New("no network list")))
	}
	for _, network := range networks {
		if network.ID != d.network {
			continue
		}
		if network.Configuration.Mode != "hostOnly" || network.Configuration.Labels["gitmoot.sandboxd.network"] != "apple-v1" {
			return fmt.Errorf("Apple network %q is not an owned host-only network", d.network)
		}
		return nil
	}
	return fmt.Errorf("Apple host-only network %q is absent", d.network)
}

func (d *AppleDriver) Create(ctx context.Context, spec Spec) (Instance, error) {
	if err := validAppleID(spec.ID); err != nil {
		return Instance{}, err
	}
	if _, ok := d.images[spec.Image]; !ok {
		return Instance{}, fmt.Errorf("image %q is not allowlisted", spec.Image)
	}
	if spec.CPUs <= 0 || spec.MemoryMiB <= 0 {
		return Instance{}, fmt.Errorf("CPU and memory limits must be positive")
	}
	if err := d.checkNetwork(ctx); err != nil {
		return Instance{}, err
	}
	_, exists, err := d.lookup(ctx, spec.ID)
	if err != nil {
		return Instance{}, err
	}
	if exists {
		return Instance{}, fmt.Errorf("container %q already exists", spec.ID)
	}
	volume, err := d.lookupVolume(ctx, spec.ID)
	if err != nil {
		return Instance{}, err
	}
	if volume {
		return Instance{}, fmt.Errorf("volume %q already exists", spec.ID)
	}
	out, err := d.output(ctx, "volume", "create", "--label", appleVolumeOwnerLabel,
		"--opt", "size="+appleVolumeSize, spec.ID)
	if err != nil {
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	if strings.TrimSpace(string(out)) != spec.ID {
		return Instance{}, errors.Join(fmt.Errorf("volume create returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupCreated(spec.ID))
	}
	out, err = d.output(ctx, "create", "--name", spec.ID,
		"--label", appleOwnerLabel, "--network", d.network, "--platform", "linux/arm64",
		"--cpus", strconv.Itoa(spec.CPUs), "--memory", strconv.Itoa(spec.MemoryMiB)+"M",
		"--read-only", "--mount", "type=volume,source="+spec.ID+",target=/home/user",
		"--tmpfs", "/tmp:size=512M,mode=1777", "--tmpfs", "/var/tmp:size=256M,mode=1777",
		"--uid", "1000", "--gid", "1000", "--entrypoint", "/bin/sleep",
		spec.Image, "2147483647")
	if err != nil {
		// A failed create can still have persisted a container. Only clean up
		// when a fresh inventory positively confirms our ownership label.
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	if strings.TrimSpace(string(out)) != spec.ID {
		return Instance{}, errors.Join(fmt.Errorf("container create returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupCreated(spec.ID))
	}
	out, err = d.output(ctx, "start", spec.ID)
	if err != nil {
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	if strings.TrimSpace(string(out)) != spec.ID {
		return Instance{}, errors.Join(fmt.Errorf("container start returned unexpected ID %q", strings.TrimSpace(string(out))), d.cleanupCreated(spec.ID))
	}
	item, found, err := d.lookup(ctx, spec.ID)
	if err != nil || !found || item.Status.State != "running" {
		if err == nil {
			err = fmt.Errorf("container %q did not become running", spec.ID)
		}
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	if _, err := d.output(ctx, "exec", "--user", "0:0", spec.ID,
		"/bin/chown", "1000:1000", "/home/user"); err != nil {
		return Instance{}, errors.Join(err, d.cleanupCreated(spec.ID))
	}
	return Instance{ID: spec.ID, Running: true}, nil
}

func (d *AppleDriver) cleanupCreated(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return d.Destroy(ctx, id)
}

func (d *AppleDriver) List(ctx context.Context) ([]Instance, error) {
	items, err := d.inventory(ctx)
	if err != nil {
		return nil, err
	}
	instances := make([]Instance, 0, len(items))
	for _, item := range items {
		if !ownedApple(item) {
			continue
		}
		if err := validAppleID(item.Configuration.ID); err != nil {
			return nil, err
		}
		switch item.Status.State {
		case "running":
			instances = append(instances, Instance{ID: item.Configuration.ID, Running: true})
		case "stopped", "stopping":
			instances = append(instances, Instance{ID: item.Configuration.ID})
		default:
			return nil, fmt.Errorf("unknown status %q for container %q", item.Status.State, item.Configuration.ID)
		}
	}
	return instances, nil
}

type appleStats struct {
	ID               string  `json:"id"`
	CPUUsageUsec     *uint64 `json:"cpuUsageUsec"`
	MemoryUsageBytes *uint64 `json:"memoryUsageBytes"`
	MemoryLimitBytes *uint64 `json:"memoryLimitBytes"`
}

func (d *AppleDriver) stats(ctx context.Context, id string) (appleStats, error) {
	out, err := d.output(ctx, "stats", "--format", "json", "--no-stream", id)
	if err != nil {
		return appleStats{}, err
	}
	var samples []appleStats
	if err := json.Unmarshal(out, &samples); err != nil {
		return appleStats{}, err
	}
	if len(samples) != 1 || samples[0].ID != id || samples[0].CPUUsageUsec == nil ||
		samples[0].MemoryUsageBytes == nil || samples[0].MemoryLimitBytes == nil || *samples[0].MemoryLimitBytes == 0 {
		return appleStats{}, fmt.Errorf("incomplete VM resource sample for %q", id)
	}
	return samples[0], nil
}

// Usage samples Apple VM counters twice to derive measured CPU utilization.
func (d *AppleDriver) Usage(ctx context.Context, id string) (Usage, error) {
	item, found, err := d.lookup(ctx, id)
	if err != nil {
		return Usage{}, err
	}
	if !found || item.Status.State != "running" {
		return Usage{}, fmt.Errorf("container %q is not running", id)
	}
	first, err := d.stats(ctx, id)
	if err != nil {
		return Usage{}, err
	}
	started := time.Now()
	second, err := d.stats(ctx, id)
	if err != nil {
		return Usage{}, err
	}
	if *second.CPUUsageUsec < *first.CPUUsageUsec || *second.MemoryUsageBytes > *second.MemoryLimitBytes {
		return Usage{}, fmt.Errorf("inconsistent VM resource sample for %q", id)
	}
	return Usage{
		CPUUsedPct:       float64(*second.CPUUsageUsec-*first.CPUUsageUsec) / float64(time.Since(started).Microseconds()) * 100,
		MemoryUsedBytes:  *second.MemoryUsageBytes,
		MemoryLimitBytes: *second.MemoryLimitBytes,
	}, nil
}

func safeGuestPath(path string) bool {
	if !strings.HasPrefix(path, "/") || path == "/" || strings.ContainsAny(path, ":\x00\n\r") || filepath.Clean(path) != path {
		return false
	}
	for _, component := range strings.Split(path, "/") {
		if component == ".." || component == "." {
			return false
		}
	}
	return true
}

// CopyIn snapshots at most 512 MiB of a regular host file and streams it to
// the guest's mounted filesystem; Apple's copy command bypasses live mounts.
func (d *AppleDriver) CopyIn(ctx context.Context, id, source, destination string) error {
	if !safeGuestPath(destination) {
		return fmt.Errorf("unsafe container destination %q", destination)
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || strings.ContainsRune(source, 0) {
		return fmt.Errorf("source must be an absolute clean host file path")
	}
	item, found, err := d.lookup(ctx, id)
	if err != nil {
		return err
	}
	if !found || item.Status.State != "running" {
		return fmt.Errorf("container %q is not running", id)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCopyBytes {
		return fmt.Errorf("copy source must be a regular file no larger than %d bytes", maxCopyBytes)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	opened, err := in.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return fmt.Errorf("copy source changed while opening")
	}
	staged, err := os.CreateTemp("", "sandboxd-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	n, err := io.Copy(staged, io.LimitReader(in, maxCopyBytes+1))
	if err != nil {
		return err
	}
	if n > maxCopyBytes {
		return fmt.Errorf("copy source exceeds %d bytes", maxCopyBytes)
	}
	if _, err := staged.Seek(0, io.SeekStart); err != nil {
		return err
	}
	c := d.command(ctx, "exec", "--interactive", "--user", "1000:1000", id,
		"/bin/sh", "-c", `umask 077; cat > "$1"`, "sh", destination)
	c.Stdin = staged
	out, err := c.CombinedOutput()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("guest copy failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Run streams stdout and stderr directly. Apple's CLI propagates guest exit
// codes, but a CLI transport failure after launch can share a guest exit code.
// Cancellation kills the host CLI; Destroy tears down remaining guest processes.
// OnStart receives the host CLI PID, not the guest PID.
func (d *AppleDriver) Run(ctx context.Context, id string, command Command, stdout, stderr io.Writer) (int, error) {
	item, found, err := d.lookup(ctx, id)
	if err != nil {
		return 0, err
	}
	if !found || item.Status.State != "running" {
		return 0, fmt.Errorf("container %q is not running", id)
	}
	if len(command.Args) == 0 || command.Args[0] == "" {
		return 0, fmt.Errorf("empty guest command")
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, 0) {
			return 0, fmt.Errorf("NUL in guest command")
		}
	}
	args := []string{"exec", "--user", "1000:1000"}
	if command.User != "" && command.User != "user" && command.User != "1000" && command.User != "1000:1000" {
		return 0, fmt.Errorf("guest user %q is not permitted", command.User)
	}
	if command.Dir != "" {
		if !safeGuestPath(command.Dir) && command.Dir != "/" {
			return 0, fmt.Errorf("unsafe guest working directory %q", command.Dir)
		}
		args = append(args, "--workdir", command.Dir)
	}
	keys := make([]string, 0, len(command.Env))
	for key, value := range command.Env {
		if !envName.MatchString(key) || strings.ContainsRune(value, 0) {
			return 0, fmt.Errorf("unsafe guest environment variable %q", key)
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+command.Env[key])
	}
	args = append(args, id)
	args = append(args, command.Args...)
	c := d.command(ctx, args...)
	c.Stdout, c.Stderr = stdout, stderr
	if err := c.Start(); err != nil {
		return 0, err
	}
	if command.OnStart != nil {
		command.OnStart(c.Process.Pid)
	}
	err = c.Wait()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// Destroy confirms both the owned VM and its bounded writable volume are gone.
// An unlabeled collision is never deleted, even if it has sandboxd's prefix.
func (d *AppleDriver) Destroy(ctx context.Context, id string) error {
	_, found, err := d.lookup(ctx, id)
	if err != nil {
		return err
	}
	if found {
		_, deleteErr := d.output(ctx, "delete", "--force", id)
		_, still, lookupErr := d.lookup(ctx, id)
		if lookupErr != nil {
			return errors.Join(deleteErr, lookupErr)
		}
		if still {
			return errors.Join(deleteErr, fmt.Errorf("container %q remains after delete", id))
		}
	}
	present, err := d.lookupVolume(ctx, id)
	if err != nil {
		return err
	}
	if present {
		_, deleteErr := d.output(ctx, "volume", "delete", id)
		still, lookupErr := d.lookupVolume(ctx, id)
		if lookupErr != nil {
			return errors.Join(deleteErr, lookupErr)
		}
		if still {
			return errors.Join(deleteErr, fmt.Errorf("volume %q remains after delete", id))
		}
	}
	return nil
}
