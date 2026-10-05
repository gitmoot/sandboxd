package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/control"
	"github.com/gitmoot/sandboxd/internal/envd"
	"github.com/gitmoot/sandboxd/internal/firewall"
	"github.com/gitmoot/sandboxd/internal/vm"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) (runErr error) {
	flags := flag.NewFlagSet("sandboxd", flag.ContinueOnError)
	driverName := flags.String("driver", "apple", "VM driver: apple (Apple container on macOS) or firecracker (Linux/KVM)")
	fc := addFirecrackerFlags(flags)
	listen := flags.String("listen", "127.0.0.1:43180", "loopback address behind private HTTPS proxy")
	database := flags.String("db", "", "durable SQLite ledger path")
	keyFile := flags.String("api-key-file", "", "0600 file containing E2B-compatible API key")
	cli := flags.String("container-cli", "/usr/local/bin/container", "absolute path to Apple container CLI")
	image := flags.String("image", "", "allowlisted guest image: Linux ARM64 OCI image (apple) or absolute read-only ext4 root image (firecracker)")
	pinImage := flags.String("pin-image", "", "trusted digest-pinned read-only bridge VM image")
	pfSocket := flags.String("pf-socket", "", "root helper Unix socket")
	template := flags.String("template", "", "allowlisted E2B-compatible template identifier")
	domain := flags.String("domain", "", "private sandbox DNS domain")
	gatewayHost := flags.String("gateway-host", "", "private HTTPS hostname for header-routed guest traffic")
	var slots firewall.SlotFlags
	flags.Var(&slots, "slot", "repeatable dedicated labeled host-only Apple network slot, one guest each: name=<network>,ipv4=<subnet>,gw=<gateway>,ipv6=<ula-prefix>")
	workerID := flags.String("worker-id", "", "stable trusted worker identity recorded for every VM")
	cpus := flags.Int("cpus", 2, "CPU limit for each VM")
	memory := flags.Int("memory-mib", 4096, "memory limit in MiB for each VM")
	relayListen := flags.String("model-relay-listen", "", "optional <first slot gateway>:<port> listener for the fixed mTLS model gateway relay")
	relayTarget := flags.String("model-relay-target", "", "loopback endpoint of a fixed SSH reverse tunnel")
	maxVMs := flags.Int("max-vms", 0, "maximum concurrent VMs; zero means one per slot (apple, never more than the slots) or 2 (firecracker)")
	maxTTL := flags.Duration("max-ttl", time.Hour, "maximum per-job lifetime")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("listen address must be an explicit loopback IP and port")
	}
	if *database == "" || *keyFile == "" || *image == "" || *template == "" || *gatewayHost == "" || *domain == "" || *workerID == "" ||
		(*driverName == "apple" && (*pinImage == "" || *pfSocket == "")) || strings.ContainsAny(*gatewayHost, "/?# ") {
		return fmt.Errorf("db, api-key-file, image, template, domain, gateway-host and worker-id are required, plus pin-image and pf-socket for the apple driver")
	}
	var slotNames []string
	switch *driverName {
	case "apple":
		if err := firewall.ValidateSlots(slots); err != nil {
			return err
		}
		slotNames = slots.Networks()
		if err := checkModelRelayListen(*relayListen, slots[0].Gateway); err != nil {
			return err
		}
	case "firecracker":
		// Firecracker guests have no host-reachable network; PF slots, the
		// bridge pin and the slot-gateway model relay are Apple-only.
		if len(slots) != 0 || *pinImage != "" || *pfSocket != "" || *relayListen != "" || *relayTarget != "" {
			return fmt.Errorf("slot, pin-image, pf-socket and model-relay flags apply only to the apple driver")
		}
		if *maxVMs == 0 {
			*maxVMs = 2
		}
		if *maxVMs < 1 || *maxVMs > 64 {
			return fmt.Errorf("max-vms must be between 1 and 64 for the firecracker driver")
		}
		slotNames = vm.FirecrackerSlotNames(*maxVMs)
	default:
		return fmt.Errorf("unknown driver %q", *driverName)
	}
	if *maxVMs == 0 {
		*maxVMs = len(slotNames)
	}
	if *maxVMs < 1 || *maxVMs > len(slotNames) {
		return fmt.Errorf("max-vms must be between 1 and the %d configured slots", len(slotNames))
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read API key: %w", err)
	}
	info, err := os.Stat(*keyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("API key must be in a regular 0600 file")
	}
	apiKey := strings.TrimSpace(string(key))
	if len(apiKey) < 8 || strings.ContainsAny(apiKey, "\r\n") {
		return fmt.Errorf("API key must be a single nonempty value of at least eight bytes")
	}
	var driver isolatedDriver
	switch *driverName {
	case "apple":
		gate, err := firewall.NewClient(*pfSocket)
		if err != nil {
			return err
		}
		apple, err := vm.NewAppleDriver(*cli, []string{*image}, slotNames, *workerID, *pinImage, gate)
		if err != nil {
			return err
		}
		if err := apple.EnsureSystem(ctx); err != nil {
			return fmt.Errorf("start Apple container services: %w", err)
		}
		if err := apple.CleanupGuests(ctx); err != nil {
			return fmt.Errorf("remove stale guest VMs before firewall admission: %w", err)
		}
		if err := apple.StartPin(ctx); err != nil {
			return fmt.Errorf("start trusted bridge pin: %w", err)
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if err := apple.CleanupGuests(cleanupCtx); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("leave PF armed; guest cleanup failed: %w", err))
				return
			}
			if err := apple.StopPin(cleanupCtx); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("leave PF armed; pin cleanup failed: %w", err))
				return
			}
			if err := gate.Disarm(cleanupCtx); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("PF anchor cleanup: %w", err))
			}
		}()
		bridges, err := gate.Arm(ctx)
		if err != nil {
			return fmt.Errorf("arm privileged firewall: %w", err)
		}
		log.Printf("sandbox guest bridges %s guarded by root PF helper", bridges)
		driver = apple
	case "firecracker":
		// Guests that survived a daemon kill keep running; the control
		// plane's reconciliation keeps those its ledger still owns.
		firecracker, shutdown, err := startFirecracker(ctx, fc, *image, slotNames)
		if err != nil {
			return err
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			runErr = errors.Join(runErr, shutdown(cleanupCtx))
		}()
		log.Printf("Firecracker guests confined by nftables table inet sbx_fc and per-VM namespaces")
		driver = firecracker
	}
	service, err := control.Open(ctx, *database, driver, control.Config{
		APIKey: apiKey, TemplateID: *template, Image: *image, Domain: *domain, WorkerID: *workerID,
		CPUs: *cpus, MemoryMiB: *memory, MaxVMs: *maxVMs, MaxTTL: *maxTTL, Slots: slotNames,
	})
	if err != nil {
		return err
	}
	defer service.Close()
	guest := &envd.Handler{Driver: driver, Authorizer: service, Domain: *domain, GatewayHost: *gatewayHost}
	handler := envd.Routes(guest, service.Handler())
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	guestSubnets := make([]netip.Prefix, len(slots))
	for i, slot := range slots {
		guestSubnets[i] = slot.IPv4
	}
	relayListener, err := openModelRelay(*relayListen, *relayTarget, guestSubnets)
	if err != nil {
		return err
	}
	if relayListener != nil {
		defer relayListener.Close()
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("sandboxd listening on %s behind private HTTPS proxy", listener.Addr())
	var relayDone chan error
	if relayListener != nil {
		relayDone = make(chan error, 1)
		go func() { relayDone <- serveModelRelay(ctx, relayListener, *relayTarget, guestSubnets) }()
		log.Printf("model relay listening on %s for %v, forwarding only to %s", relayListener.Addr(), guestSubnets, *relayTarget)
	}
	guardCtx, stopGuard := context.WithCancel(context.Background())
	defer stopGuard()
	guardFailed := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-guardCtx.Done():
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(guardCtx, 5*time.Second)
				err := driver.Ready(checkCtx)
				cancel()
				if err != nil && guardCtx.Err() == nil {
					guardFailed <- err
					return
				}
			}
		}
	}()
	select {
	case err := <-guardFailed:
		_ = server.Close()
		return fmt.Errorf("sandbox isolation lost; stopping guest work: %w", err)
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-relayDone:
		_ = server.Close()
		if err == nil && ctx.Err() != nil {
			return nil
		}
		if err == nil {
			return errors.New("model relay stopped unexpectedly")
		}
		return fmt.Errorf("model relay stopped: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}
