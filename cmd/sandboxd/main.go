package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
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
	listen := flags.String("listen", "127.0.0.1:43180", "loopback address behind private HTTPS proxy")
	database := flags.String("db", "", "durable SQLite ledger path")
	keyFile := flags.String("api-key-file", "", "0600 file containing E2B-compatible API key")
	cli := flags.String("container-cli", "/usr/local/bin/container", "absolute path to Apple container CLI")
	image := flags.String("image", "", "allowlisted Linux ARM64 OCI image")
	pinImage := flags.String("pin-image", "", "trusted digest-pinned read-only bridge VM image")
	pfSocket := flags.String("pf-socket", "", "root helper Unix socket")
	template := flags.String("template", "", "allowlisted E2B-compatible template identifier")
	domain := flags.String("domain", "", "private sandbox DNS domain")
	gatewayHost := flags.String("gateway-host", "", "private HTTPS hostname for header-routed guest traffic")
	network := flags.String("network", "", "dedicated labeled host-only Apple container network")
	workerID := flags.String("worker-id", "", "stable trusted worker identity recorded for every VM")
	cpus := flags.Int("cpus", 2, "CPU limit for each VM")
	memory := flags.Int("memory-mib", 4096, "memory limit in MiB for each VM")
	relayListen := flags.String("model-relay-listen", "", "optional IPv4 listener for fixed mTLS model gateway relay")
	relayTarget := flags.String("model-relay-target", "", "loopback endpoint of a fixed SSH reverse tunnel")
	relayGuestCIDR := flags.String("model-relay-guest-cidr", "", "private IPv4 guest subnet permitted to connect")
	maxVMs := flags.Int("max-vms", 2, "maximum concurrent VMs")
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
	if *database == "" || *keyFile == "" || *image == "" || *pinImage == "" || *pfSocket == "" ||
		*template == "" || *gatewayHost == "" || *domain == "" || *network == "" || *workerID == "" ||
		strings.ContainsAny(*gatewayHost, "/?# ") {
		return fmt.Errorf("db, api-key-file, image, pin-image, pf-socket, template, domain, gateway-host, network and worker-id are required")
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
	gate, err := firewall.NewClient(*pfSocket)
	if err != nil {
		return err
	}
	driver, err := vm.NewAppleDriver(*cli, []string{*image}, *network, *workerID, *pinImage, gate)
	if err != nil {
		return err
	}
	if err := driver.CleanupGuests(ctx); err != nil {
		return fmt.Errorf("remove stale guest VMs before firewall admission: %w", err)
	}
	if err := driver.StartPin(ctx); err != nil {
		return fmt.Errorf("start trusted bridge pin: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := driver.CleanupGuests(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("leave PF armed; guest cleanup failed: %w", err))
			return
		}
		if err := driver.StopPin(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("leave PF armed; pin cleanup failed: %w", err))
			return
		}
		if err := gate.Disarm(cleanupCtx); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("PF anchor cleanup: %w", err))
		}
	}()
	bridge, err := gate.Arm(ctx)
	if err != nil {
		return fmt.Errorf("arm privileged firewall: %w", err)
	}
	log.Printf("sandbox guest bridge %s guarded by root PF helper", bridge)
	service, err := control.Open(ctx, *database, driver, control.Config{
		APIKey: apiKey, TemplateID: *template, Image: *image, Domain: *domain, WorkerID: *workerID,
		CPUs: *cpus, MemoryMiB: *memory, MaxVMs: *maxVMs, MaxTTL: *maxTTL,
	})
	if err != nil {
		return err
	}
	defer service.Close()
	guest := &envd.Handler{Driver: driver, Authorizer: service, Domain: *domain, GatewayHost: *gatewayHost}
	api := service.Handler()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/files" || r.URL.Path == "/process.Process/Start" {
			guest.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	relayListener, guestSubnet, err := openModelRelay(*relayListen, *relayTarget, *relayGuestCIDR)
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
		go func() { relayDone <- serveModelRelay(ctx, relayListener, *relayTarget, guestSubnet) }()
		log.Printf("model relay listening on %s for %s, forwarding only to %s", relayListener.Addr(), guestSubnet, *relayTarget)
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
