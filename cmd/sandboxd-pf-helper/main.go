// sandboxd-pf-helper is installed as a root-owned launchd service. Its socket
// is accessible only to the dedicated unprivileged sandboxd worker account.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/gitmoot/sandboxd/internal/firewall"
	"github.com/gitmoot/sandboxd/internal/helpersvc"
)

// version is the release tag, set at build time by the release workflow
// (-ldflags "-X main.version=vX.Y.Z"). A local build says "dev".
var version = "dev"

const usage = `usage:
  sandboxd-pf-helper run [flags]       serve the helper (what the launchd job runs)
  sandboxd-pf-helper version
  sudo sandboxd-pf-helper install [flags]
  sudo sandboxd-pf-helper update [--version vX.Y.Z]`

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "run":
		return serve(ctx, args[1:])
	case "version":
		if len(args) != 1 {
			return errors.New(usage)
		}
		fmt.Fprintln(stdout, version)
		return nil
	case "install":
		flags := flag.NewFlagSet("install", flag.ContinueOnError)
		var opts helpersvc.InstallOptions
		flags.StringVar(&opts.WorkerID, "worker-id", helpersvc.DefaultWorkerID, "stable worker identity")
		flags.StringVar(&opts.PinImage, "pin-image", helpersvc.DefaultPinImage, "trusted digest-pinned bridge VM image")
		flags.StringVar(&opts.ContainerCLI, "container-cli", helpersvc.DefaultContainerCLI, "root-owned Apple container CLI")
		flags.StringVar(&opts.MainRulesSHA256, "main-rules-sha256", "", "SHA-256 of the reviewed pfctl -sr output (default: of the current output)")
		flags.IntVar(&opts.ModelRelayPort, "model-relay-port", 0, "fixed model relay TCP port on the first slot's gateway, open to every slot; zero retains deny-only PF")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		return helpersvc.MacHost(stdout).Install(ctx, opts, version)
	case "update":
		flags := flag.NewFlagSet("update", flag.ContinueOnError)
		want := flags.String("version", "", "install this release tag, even if older (default: the latest)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return fmt.Errorf("unexpected arguments")
		}
		return helpersvc.MacHost(stdout).Update(ctx, *want, version)
	}
	return errors.New(usage)
}

func serve(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sandboxd-pf-helper run", flag.ContinueOnError)
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
	modelRelayPort := flags.Int("model-relay-port", 0, "fixed model relay TCP port on the first slot's gateway, open to every slot; zero retains deny-only PF")
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
	if err := helpersvc.EnsureSocketDir(*socket); err != nil {
		return err
	}
	return server.Serve(ctx)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
