package main

import (
	"context"
	"flag"
	"fmt"
	"net"
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
	root, firecracker, jailer, kernel  *string
	uidBase, homeDiskMiB, diskFloorMiB *int
	hostPort                           *int
	bootTimeout                        *time.Duration
	consoleLog                         *bool
	deny                               *egress.PrefixFlags
}

func addFirecrackerFlags(flags *flag.FlagSet) firecrackerFlags {
	deny := &egress.PrefixFlags{}
	flags.Var(deny, "fc-deny-cidr", "firecracker: repeatable extra guest egress deny prefix, e.g. a cloud provider's public metadata endpoint")
	return firecrackerFlags{
		root:         flags.String("fc-root", "/var/lib/sandboxd-fc", "firecracker: install and state directory; jails and records live under it"),
		firecracker:  flags.String("fc-firecracker", "", "firecracker: Firecracker binary (default <fc-root>/bin/firecracker)"),
		jailer:       flags.String("fc-jailer", "", "firecracker: jailer binary (default <fc-root>/bin/jailer)"),
		kernel:       flags.String("fc-kernel", "", "firecracker: uncompressed guest kernel on the fc-root filesystem"),
		uidBase:      flags.Int("fc-uid-base", 2900000, "firecracker: first host UID; slot i runs its VMM as base+i and its NAT as base+1000+i"),
		homeDiskMiB:  flags.Int("fc-home-disk-mib", 10240, "firecracker: size of each VM's private writable /home/user disk"),
		diskFloorMiB: flags.Int("fc-disk-floor-mib", 8192, "firecracker: refuse to create a VM unless this much disk stays free beyond its home disk"),
		hostPort: flags.Int("fc-host-port", 0, "firecracker: the one host TCP port guests may reach, as 10.0.2.2:<port> = the host's 127.0.0.1:<port> "+
			"(e.g. a credential gateway); 0 allows none"),
		bootTimeout: flags.Duration("fc-boot-timeout", time.Minute, "firecracker: maximum time for the guest agent to answer after boot"),
		consoleLog:  flags.Bool("fc-console-log", false, "firecracker: keep each guest's serial console in its jail for debugging"),
		deny:        deny,
	}
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
