//go:build sandboxd_devdriver && linux

// Command sandboxd-dev serves the real sandboxd control plane and guest data
// plane on loopback with the CI-only devvm driver: every "VM" is a group of
// local processes in a temporary directory. It has no isolation, PF helper,
// slots or model relay and exists only for conformance suites. It builds only
// with -tags sandboxd_devdriver; release builds never set that tag.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/sandboxd/internal/control"
	"github.com/gitmoot/sandboxd/internal/envd"
	"github.com/gitmoot/sandboxd/internal/vm/devvm"
)

// devImage names the dev driver's only "image"; nothing is pulled.
const devImage = "sandboxd-devvm:local-processes"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string) (runErr error) {
	flags := flag.NewFlagSet("sandboxd-dev", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:43180", "loopback address")
	database := flags.String("db", "", "SQLite ledger path")
	keyFile := flags.String("api-key-file", "", "0600 file containing the test API key")
	stateDir := flags.String("state-dir", "", "absent or empty directory for guest process trees")
	template := flags.String("template", "review-arm64", "primary gitmoot-strict template identifier")
	registered := control.TemplateFlags{FixedImage: devImage}
	flags.Var(&registered, "register-template", "repeatable template: id=<id>,profile=gitmoot-strict|e2b[,alias=<name>]...[,envd-version=X.Y.Z]; the image is always the dev image")
	tokenSecretFile := flags.String("token-secret-file", "", "0600 file deriving e2b envd tokens; default: a random secret for this process")
	domain := flags.String("domain", "", "sandbox DNS domain reported to clients")
	gatewayHost := flags.String("gateway-host", "127.0.0.1", "host name for header-routed guest traffic")
	maxVMs := flags.Int("max-vms", 4, "maximum concurrent guests")
	maxTTL := flags.Duration("max-ttl", time.Hour, "maximum per-sandbox lifetime")
	cpus := flags.Int("cpus", 2, "CPU count reported for each guest")
	memory := flags.Int("memory-mib", 1024, "memory size reported for each guest")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen address must be an explicit loopback IP and port")
	}
	if *database == "" || *keyFile == "" || *stateDir == "" || *domain == "" || *gatewayHost == "" {
		return errors.New("db, api-key-file, state-dir, domain and gateway-host are required")
	}
	if *maxVMs < 1 || *maxVMs > 64 {
		return errors.New("max-vms must be between 1 and 64")
	}
	apiKey, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	tokenSecret := make([]byte, 32)
	if *tokenSecretFile != "" {
		if tokenSecret, err = control.ReadTokenSecret(*tokenSecretFile); err != nil {
			return err
		}
	} else if _, err := rand.Read(tokenSecret); err != nil {
		return err
	}
	root, err := filepath.Abs(*stateDir)
	if err != nil {
		return err
	}
	driver, err := devvm.New(root)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, driver.Close(cleanup), os.Remove(root))
	}()
	slots := make([]string, *maxVMs)
	for i := range slots {
		slots[i] = fmt.Sprintf("devvm-slot-%d", i)
	}
	service, err := control.Open(ctx, *database, driver, control.Config{
		APIKey: apiKey, TemplateID: *template, Image: devImage, Domain: *domain, WorkerID: "sandboxd-devvm",
		CPUs: *cpus, MemoryMiB: *memory, MaxVMs: *maxVMs, MaxTTL: *maxTTL, Slots: slots,
		DriverName: "devvm", Templates: registered.Templates, TokenSecret: tokenSecret,
	})
	if err != nil {
		return err
	}
	defer service.Close()
	guest := &envd.Handler{Driver: service.Guests(), Authorizer: service, Domain: *domain, GatewayHost: *gatewayHost}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: envd.Routes(guest, service.Handler()), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	log.Printf("sandboxd-dev listening on http://%s (devvm driver, NO isolation, state %s)", listener.Addr(), root)
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

func readKey(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("API key must be in a regular 0600 file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read API key: %w", err)
	}
	key := strings.TrimSpace(string(raw))
	if len(key) < 8 || strings.ContainsAny(key, "\r\n") {
		return "", errors.New("API key must be a single value of at least eight bytes")
	}
	return key, nil
}
