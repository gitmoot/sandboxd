package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/gitmoot/sandboxd/internal/egress"
	"github.com/gitmoot/sandboxd/internal/vm"
)

// isolatedDriver is a VM driver whose isolation boundary the daemon re-checks
// every second, stopping guest work when it is lost.
type isolatedDriver interface {
	vm.Driver
	Ready(context.Context) error
}

// firecrackerFlags configure the Linux/KVM worker (docs/firecracker.md).
type firecrackerFlags struct {
	instance                           *string
	root, firecracker, jailer, kernel  *string
	uidBase, homeDiskMiB, diskFloorMiB *int
	hostPort                           *int
	bootTimeout                        *time.Duration
	consoleLog, balloon                *bool
	deny                               *egress.PrefixFlags
	volumeBudgetMiB, volumeMiB         *int
	volumeDir                          *string
}

// fcVolumeFlags are the flags that only a Firecracker gateway takes.
var fcVolumeFlags = []string{"fc-volume-budget-mib", "fc-volume-mib", "fc-volume-dir"}

func addFirecrackerFlags(flags *flag.FlagSet) firecrackerFlags {
	deny := &egress.PrefixFlags{}
	flags.Var(deny, "fc-deny-cidr", "firecracker: repeatable extra guest egress deny prefix, e.g. a cloud provider's public metadata endpoint")
	return firecrackerFlags{
		instance: flags.String("fc-instance", "", "firecracker: name of one of several instances on this host (lowercase, up to 12 characters); "+
			"empty is the default instance. Each needs its own -fc-root, -fc-uid-base, -listen and -db"),
		root:         flags.String("fc-root", vm.FirecrackerDefaultRoot, "firecracker: install and state directory; jails and records live under it"),
		firecracker:  flags.String("fc-firecracker", "", "firecracker: Firecracker binary (default <fc-root>/bin/firecracker)"),
		jailer:       flags.String("fc-jailer", "", "firecracker: jailer binary (default <fc-root>/bin/jailer)"),
		kernel:       flags.String("fc-kernel", "", "firecracker: uncompressed guest kernel on the fc-root filesystem"),
		uidBase:      flags.Int("fc-uid-base", vm.FirecrackerDefaultUIDBase, "firecracker: first host UID; slot i runs its VMM as base+i and its NAT as base+1000+i"),
		homeDiskMiB:  flags.Int("fc-home-disk-mib", 10240, "firecracker: size of each VM's private writable /home/user disk"),
		diskFloorMiB: flags.Int("fc-disk-floor-mib", 8192, "firecracker: refuse to create a VM unless this much disk stays free beyond its home disk"),
		hostPort: flags.Int("fc-host-port", 0, "firecracker: the one host TCP port guests may reach, as 10.0.2.2:<port> = the host's 127.0.0.1:<port> "+
			"(e.g. a credential gateway); 0 allows none"),
		bootTimeout: flags.Duration("fc-boot-timeout", time.Minute, "firecracker: maximum time for the guest agent to answer after boot"),
		consoleLog:  flags.Bool("fc-console-log", false, "firecracker: keep each guest's serial console in its jail for debugging"),
		balloon: flags.Bool("fc-balloon", false, "firecracker: give each VM a balloon device with free page reporting, "+
			"and have an idle guest drop its caches, so memory the guest no longer uses goes back to the host (needs CONFIG_PAGE_REPORTING in the guest kernel)"),
		deny:            deny,
		volumeBudgetMiB: flags.Int("fc-volume-budget-mib", 0, "firecracker gateway: total MiB of durable e2b volumes; 0 (the default) disables volumes"),
		volumeMiB:       flags.Int("fc-volume-mib", 512, "firecracker gateway: size of each new volume"),
		volumeDir:       flags.String("fc-volume-dir", "", "firecracker gateway: volume directory on the fc-root filesystem (default <fc-root>/volumes)"),
	}
}

// checkFirecrackerVolumeFlags refuses volume flags anywhere but on a
// Firecracker gateway: an enrolled worker or another driver keeps none.
func checkFirecrackerVolumeFlags(flags *flag.FlagSet, driver string, workerMode bool) error {
	set := false
	flags.Visit(func(f *flag.Flag) { set = set || slices.Contains(fcVolumeFlags, f.Name) })
	if set && (workerMode || driver != "firecracker") {
		return fmt.Errorf("fc-volume flags apply only to a firecracker gateway, not to a -worker-key-file worker or another driver")
	}
	return nil
}

// checkFirecrackerHostPort validates -fc-host-port: a TCP port other than
// SSH and other than sandboxd's own -listen port, which guests must never
// reach.
func checkFirecrackerHostPort(port int, listen string) error {
	if err := vm.ValidateFirecrackerHostPort(port); err != nil {
		return fmt.Errorf("fc-host-port: %w", err)
	}
	if _, own, err := net.SplitHostPort(listen); err == nil && port != 0 {
		if n, err := strconv.Atoi(own); err == nil && n == port {
			return fmt.Errorf("fc-host-port must not be sandboxd's own listen port %d", port)
		}
	}
	return nil
}
