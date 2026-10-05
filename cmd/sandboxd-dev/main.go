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
	"os/exec"
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
	// The envd guest root helper (see devvm.Envd) is this binary too.
	if len(os.Args) > 1 && os.Args[1] == devvm.EnvdGuestCommand {
		if err := devvm.RunEnvdGuest(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if handled, err := devvm.RunEnvdGuestInit(os.Args[1:]); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
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
	portHosts := flags.Bool("port-hosts", false, "also route exposed guest ports by wildcard host <port>-<id>.<domain> (needs wildcard DNS and TLS for *.<domain> in front of sandboxd); without it guest ports are reached only via -gateway-host and routing headers")
	portStreams := flags.Int("port-max-streams", envd.DefaultMaxPortStreams, "maximum concurrent guest port requests (WebSocket and other upgraded streams included) per e2b sandbox; more are refused with 429")
	readyTimeout := flags.Duration("template-ready-timeout", control.DefaultReadyTimeout, "how long create waits for an e2b template's start and ready commands before it destroys the sandbox and answers 503")
	maxVMs := flags.Int("max-vms", 4, "maximum concurrent guests")
	maxTTL := flags.Duration("max-ttl", time.Hour, "maximum per-sandbox lifetime")
	cpus := flags.Int("cpus", 2, "CPU count reported for each guest")
	memory := flags.Int("memory-mib", 1024, "memory size reported for each guest")
	envdBinary := flags.String("envd", "", "upstream envd binary for e2b-profile guests; without it e2b sandboxes cannot start. "+
		"envd guests need root: as root they start directly, otherwise through 'sudo -n'")
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
	if *portStreams < 1 || *readyTimeout <= 0 {
		return errors.New("port-max-streams must be at least 1 and template-ready-timeout positive")
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
	envdGuests, err := envdConfig(*envdBinary)
	if err != nil {
		return err
	}
	driver, err := devvm.New(root, envdGuests)
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
		CPUs: *cpus, MemoryMiB: *memory, MaxVMs: *maxVMs, MaxTTL: *maxTTL, ReadyTimeout: *readyTimeout, Slots: slots,
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
	server := &http.Server{Handler: envd.Routes(guest, portProxy(service, *domain, *gatewayHost, *portHosts, *portStreams), service.Handler()), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
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

// envdConfig runs envd guests through this binary as the root helper.
func envdConfig(binary string) (devvm.Envd, error) {
	if binary == "" {
		return devvm.Envd{}, nil
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		return devvm.Envd{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return devvm.Envd{}, err
	}
	helper := []string{self}
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return devvm.Envd{}, fmt.Errorf("envd guests need root or sudo: %w", err)
		}
		helper = []string{sudo, "-n", self}
	}
	return devvm.Envd{Binary: binary, Helper: helper}, nil
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

// portProxy is envd.NewProxy with host-based guest port routing and the
// per-sandbox stream cap set.
func portProxy(sandboxes envd.E2BSandboxes, domain, gatewayHost string, portHosts bool, maxStreams int) *envd.Proxy {
	proxy := envd.NewProxy(sandboxes, domain, gatewayHost)
	proxy.PortHosts, proxy.MaxPortStreams = portHosts, maxStreams
	return proxy
}
