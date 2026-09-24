// sandboxd-pf-helper is installed as a root-owned launchd service. Its socket
// is accessible only to the dedicated unprivileged sandboxd worker account.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitmoot/sandboxd/internal/firewall"
)

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sandboxd-pf-helper", flag.ContinueOnError)
	socket := flags.String("socket", "", "socket in a root-owned directory")
	uid := flags.Int("worker-uid", -1, "dedicated unprivileged sandboxd worker UID")
	gid := flags.Int("worker-gid", -1, "dedicated unprivileged sandboxd worker GID")
	home := flags.String("worker-home", "", "dedicated worker home containing the Apple container socket")
	workerID := flags.String("worker-id", "", "stable worker identity")
	cli := flags.String("container-cli", "/usr/local/bin/container", "root-owned Apple container CLI")
	network := flags.String("network", "", "owned Apple host-only network")
	pinImage := flags.String("pin-image", "", "trusted digest-pinned bridge VM image")
	gateway := flags.String("gateway-ipv4", "", "pinned dedicated network gateway")
	ipv4 := flags.String("network-ipv4", "", "pinned dedicated network IPv4 subnet")
	prefix := flags.String("network-ipv6", "", "pinned dedicated network ULA prefix")
	mainHash := flags.String("main-rules-sha256", "", "SHA-256 of the reviewed pfctl -sr output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	server, err := firewall.NewServer(firewall.Config{
		SocketPath: *socket, WorkerUID: *uid, WorkerGID: *gid,
		WorkerHome: *home, WorkerID: *workerID, ContainerCLI: *cli,
		Network: *network, PinImage: *pinImage,
		GatewayIPv4: *gateway, IPv4Subnet: *ipv4, IPv6Prefix: *prefix, MainRulesSHA256: *mainHash,
	})
	if err != nil {
		return err
	}
	return server.Serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
