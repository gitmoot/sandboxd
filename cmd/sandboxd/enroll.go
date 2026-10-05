package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gitmoot/sandboxd/internal/control"
	"github.com/gitmoot/sandboxd/internal/worker"
)

// enrollFlags collects repeatable -enroll id=<worker>,url=<https URL>,key-file=<path>
// values: remote workers the gateway schedules onto besides its own driver.
type enrollFlags []enrollment

type enrollment struct{ id, url, keyFile string }

func (f *enrollFlags) String() string {
	ids := make([]string, len(*f))
	for i, e := range *f {
		ids[i] = e.id
	}
	return strings.Join(ids, ",")
}

func (f *enrollFlags) Set(value string) error {
	var e enrollment
	for _, field := range strings.Split(value, ",") {
		name, v, ok := strings.Cut(field, "=")
		if !ok || v == "" {
			return fmt.Errorf("enroll field %q must be name=value", field)
		}
		switch name {
		case "id":
			e.id = v
		case "url":
			e.url = v
		case "key-file":
			e.keyFile = v
		default:
			return fmt.Errorf("unknown enroll field %q", name)
		}
	}
	if e.id == "" || e.url == "" || e.keyFile == "" {
		return fmt.Errorf("enroll needs id, url and key-file")
	}
	*f = append(*f, e)
	return nil
}

// remotes builds the enrolled workers' authenticated clients. The local
// worker ID may not be reused by a remote worker.
func (f enrollFlags) remotes(localID string) ([]control.Remote, error) {
	remotes := make([]control.Remote, 0, len(f))
	seen := map[string]bool{localID: true}
	for _, e := range f {
		if seen[e.id] {
			return nil, fmt.Errorf("worker %q is enrolled twice", e.id)
		}
		seen[e.id] = true
		key, err := readSecretFile(e.keyFile, 16)
		if err != nil {
			return nil, fmt.Errorf("worker %s key: %w", e.id, err)
		}
		client, err := worker.NewClient(e.id, e.url, key, nil)
		if err != nil {
			return nil, err
		}
		remotes = append(remotes, control.Remote{ID: e.id, Member: client})
	}
	return remotes, nil
}

// templateArchFlags collects repeatable -template-arch <template>=<arch>
// values: templates served by enrolled workers and the guest architecture each
// requires.
type templateArchFlags map[string]string

func (f templateArchFlags) String() string {
	parts := make([]string, 0, len(f))
	for template, arch := range f {
		parts = append(parts, template+"="+arch)
	}
	return strings.Join(parts, ",")
}

func (f templateArchFlags) Set(value string) error {
	template, arch, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(template) == "" || arch != "arm64" && arch != "amd64" {
		return fmt.Errorf("template-arch %q must be <template>=arm64|amd64", value)
	}
	if _, duplicate := f[template]; duplicate {
		return fmt.Errorf("template %q is registered twice", template)
	}
	f[template] = arch
	return nil
}

// mergeTemplates combines -register-template entries with -template-arch
// shorthands; a template named by both must agree on its architecture.
func mergeTemplates(registered map[string]control.Template, archs templateArchFlags) (map[string]control.Template, error) {
	templates := maps.Clone(registered)
	if templates == nil {
		templates = make(map[string]control.Template)
	}
	for id, arch := range archs {
		template := templates[id]
		if template.Arch != "" && template.Arch != arch {
			return nil, fmt.Errorf("template %q is registered for %s and %s", id, template.Arch, arch)
		}
		template.Arch = arch
		templates[id] = template
	}
	return templates, nil
}

// readSecretFile reads a single-line secret from a regular file that only its
// owner can read.
func readSecretFile(path string, minBytes int) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("secret must be in a regular 0600 file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(data))
	if len(secret) < minBytes || strings.ContainsAny(secret, "\r\n") {
		return "", fmt.Errorf("secret must be a single value of at least %d bytes", minBytes)
	}
	return secret, nil
}

// driverArch is the guest architecture each VM driver runs: Apple container
// runs Linux ARM64 guests, the Firecracker worker Linux x86_64 guests.
func driverArch(driver string) string {
	switch driver {
	case "apple":
		return "arm64"
	case "firecracker":
		return "amd64"
	}
	return ""
}

// workerDeclaration is what a -worker-key-file worker declares to the gateway
// that enrolls it.
func workerDeclaration(driver, id string, templates map[string]string, cpus, memoryMiB, maxVMs int, slots []string) worker.Declaration {
	return worker.Declaration{ID: id, Arch: driverArch(driver), Driver: driver, Templates: templates,
		CPUs: cpus, MemoryMiB: memoryMiB, MaxVMs: maxVMs, Slots: slices.Clone(slots)}
}

// forgetWorker asks a running gateway to release the live reservations of a
// worker that is not online, without proof that its VMs are gone.
func forgetWorker(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sandboxd forget-worker", flag.ContinueOnError)
	id := flags.String("id", "", "worker ID whose live sandboxes are released without proof of teardown")
	confirm := flags.Bool("confirm", false, "required: accept that the worker's VMs may still exist")
	apiURL := flags.String("api-url", "http://127.0.0.1:43180", "running gateway's control API: its loopback -listen address or private HTTPS URL")
	keyFile := flags.String("api-key-file", "", "0600 file containing the gateway's API key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *id == "" || *keyFile == "" {
		return errors.New("usage: sandboxd forget-worker -id <worker-id> -confirm -api-key-file <file> [-api-url <url>]")
	}
	if !*confirm {
		return errors.New("forget-worker releases reservations without proof that the worker's VMs are gone; rerun with -confirm")
	}
	base, err := url.Parse(*apiURL)
	if err != nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		!(base.Scheme == "https" && base.Host != "" || base.Scheme == "http" && isLoopbackHost(base.Hostname())) {
		return errors.New("api-url must be https://..., or http:// to a loopback IP")
	}
	key, err := readSecretFile(*keyFile, 8)
	if err != nil {
		return fmt.Errorf("API key: %w", err)
	}
	endpoint := strings.TrimSuffix(base.String(), "/") + "/sandboxd/workers/" + url.PathEscape(*id) + "/forget"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{"confirm":true}`))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-API-Key", key)
	response, err := (&http.Client{Timeout: time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway refused forget-worker %s: %s %s", *id, response.Status, strings.TrimSpace(string(body)))
	}
	var answer struct {
		WorkerID   string   `json:"workerID"`
		Unverified []string `json:"unverified"`
	}
	if err := json.Unmarshal(body, &answer); err != nil || answer.WorkerID != *id {
		return fmt.Errorf("malformed forget-worker answer: %s", strings.TrimSpace(string(body)))
	}
	fmt.Fprintf(stdout, "worker %s: released %d sandbox reservation(s) as destroyed-unverified; their VMs were NOT proven gone\n", *id, len(answer.Unverified))
	for _, sandbox := range answer.Unverified {
		fmt.Fprintln(stdout, sandbox)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
