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
	var slots firewall.SlotFlags
	flags.Var(&slots, "slot", "repeatable owned Apple host-only network slot: name=<network>,ipv4=<subnet>,gw=<gateway>,ipv6=<ula-prefix>")
	pinImage := flags.String("pin-image", "", "trusted digest-pinned bridge VM image")
	mainHash := flags.String("main-rules-sha256", "", "SHA-256 of the reviewed pfctl -sr output")
	modelRelayPort := flags.Int("model-relay-port", 0, "fixed guest-to-gateway model TCP port; zero retains deny-only PF")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	server, err := firewall.NewServer(firewall.Config{
		SocketPath: *socket, WorkerUID: *uid, WorkerGID: *gid,
		WorkerHome: *home, WorkerID: *workerID, ContainerCLI: *cli,
		Slots: slots, PinImage: *pinImage, MainRulesSHA256: *mainHash,
		ModelRelayPort: *modelRelayPort,
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
