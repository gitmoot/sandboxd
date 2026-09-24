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
	"github.com/gitmoot/sandboxd/internal/vm"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("sandboxd", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:43180", "loopback address behind private HTTPS proxy")
	database := flags.String("db", "", "durable SQLite ledger path")
	keyFile := flags.String("api-key-file", "", "0600 file containing E2B-compatible API key")
	cli := flags.String("container-cli", "/usr/local/bin/container", "absolute path to Apple container CLI")
	image := flags.String("image", "", "allowlisted Linux ARM64 OCI image")
	template := flags.String("template", "", "allowlisted E2B-compatible template identifier")
	domain := flags.String("domain", "", "private sandbox DNS domain")
	gatewayHost := flags.String("gateway-host", "", "private HTTPS hostname for header-routed guest traffic")
	network := flags.String("network", "", "dedicated labeled host-only Apple container network")
	workerID := flags.String("worker-id", "", "stable trusted worker identity recorded for every VM")
	cpus := flags.Int("cpus", 2, "CPU limit for each VM")
	memory := flags.Int("memory-mib", 4096, "memory limit in MiB for each VM")
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
	if *database == "" || *keyFile == "" || *image == "" || *template == "" || *gatewayHost == "" || *domain == "" || *network == "" || *workerID == "" || strings.ContainsAny(*gatewayHost, "/?# ") {
		return fmt.Errorf("db, api-key-file, image, template, domain, gateway-host, network and worker-id are required")
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
	driver, err := vm.NewAppleDriver(*cli, []string{*image}, *network, *workerID)
	if err != nil {
		return err
	}
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
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 1 << 20}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("sandboxd listening on %s behind private HTTPS proxy", listener.Addr())
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}
