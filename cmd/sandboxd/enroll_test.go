package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollFlagsBuildAuthenticatedWorkers(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "linux.key")
	if err := os.WriteFile(key, []byte("worker-key-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var enrolls enrollFlags
	if err := enrolls.Set("id=linux-1,url=https://linux-1.tailnet.example:8444,key-file=" + key); err != nil {
		t.Fatal(err)
	}
	remotes, err := enrolls.remotes("mac-local")
	if err != nil || len(remotes) != 1 || remotes[0].ID != "linux-1" || remotes[0].Member == nil {
		t.Fatalf("remotes = %+v, %v", remotes, err)
	}
	if _, err := enrolls.remotes("linux-1"); err == nil {
		t.Fatal("remote worker reused the local worker ID")
	}
	for _, bad := range []string{"id=x,url=https://h", "id=x,url=https://h,key-file=" + key + ",extra=1", "id=x,url"} {
		var f enrollFlags
		if err := f.Set(bad); err == nil {
			t.Fatalf("accepted -enroll %q", bad)
		}
	}
	// Plain HTTP to a non-loopback worker would expose the worker key.
	var plain enrollFlags
	if err := plain.Set("id=linux-1,url=http://100.64.0.2:8444,key-file=" + key); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.remotes("mac-local"); err == nil {
		t.Fatal("accepted a cleartext non-loopback worker URL")
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := enrolls.remotes("mac-local"); err == nil {
		t.Fatal("accepted a group-readable worker key")
	}
}

func TestTemplateArchFlagsRequireKnownArchitecture(t *testing.T) {
	archs := make(templateArchFlags)
	if err := archs.Set("review-amd64=amd64"); err != nil || archs["review-amd64"] != "amd64" {
		t.Fatalf("archs = %v, %v", archs, err)
	}
	for _, bad := range []string{"review-amd64=arm64", "x=riscv64", "=amd64", "noarch"} {
		if err := archs.Set(bad); err == nil {
			t.Fatalf("accepted -template-arch %q", bad)
		}
	}
}

func TestWorkerDeclaresItsRealDriverAndArchitecture(t *testing.T) {
	for _, tc := range []struct{ driver, arch, image string }{
		{"firecracker", "amd64", "/var/lib/sandboxd-fc/images/review-amd64.ext4"},
		{"apple", "arm64", "linux-arm64"},
	} {
		decl := workerDeclaration(tc.driver, "worker-1", "review", tc.image, 2, 1024, 1, []string{"sbx0"})
		if decl.Arch != tc.arch || decl.Driver != tc.driver || decl.Templates["review"] != tc.image || decl.Validate() != nil {
			t.Fatalf("%s worker declared %+v (%v)", tc.driver, decl, decl.Validate())
		}
	}
}

func TestRequiredFlagsPerModeAndDriver(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "worker.key")
	if err := os.WriteFile(key, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fcWorker := []string{"-driver", "firecracker", "-image", "/x.ext4", "-template", "review-amd64", "-worker-id", "linux-1", "-worker-key-file", key}
	for _, tc := range []struct {
		args []string
		want string
	}{
		// A firecracker worker needs no gateway flags; it gets as far as its key.
		{fcWorker, "worker key"},
		{append([]string{"-max-vms", "1"}, fcWorker...), "worker key"},
		// An apple worker still needs its PF helper and bridge pin.
		{[]string{"-image", "linux-arm64", "-template", "t", "-worker-id", "mac-1", "-worker-key-file", key}, "plus pin-image and pf-socket for the apple driver"},
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-template", "t", "-worker-key-file", key}, "worker-id are required"},
		{append([]string{"-enroll", "id=x,url=https://h,key-file=" + key}, fcWorker...), "cannot enroll workers"},
		{[]string{"-driver", "none", "-worker-key-file", key}, "cannot enroll workers"},
		// A gateway still needs its database, API key, domain and gateway host.
		{[]string{"-driver", "firecracker", "-image", "/x.ext4", "-template", "t", "-worker-id", "linux-1"}, "also needs db, api-key-file, domain and gateway-host"},
		// A gateway with no local VMs needs workers to schedule onto.
		{[]string{"-driver", "none", "-db", "/nonexistent/db", "-api-key-file", "/nonexistent/key", "-domain", "d.example", "-gateway-host", "gw"}, "needs at least one -enroll worker"},
		{[]string{"-driver", "none", "-db", "/nonexistent/db", "-api-key-file", "/nonexistent/key", "-domain", "d.example", "-gateway-host", "gw",
			"-enroll", "id=linux-1,url=https://linux-1.example,key-file=" + key, "-max-vms", "2"}, "do not apply"},
		{[]string{"-driver", "none", "-db", "/nonexistent/db", "-api-key-file", "/nonexistent/key", "-domain", "d.example", "-gateway-host", "gw",
			"-enroll", "id=linux-1,url=https://linux-1.example,key-file=" + key}, "read API key"},
	} {
		err := run(context.Background(), tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %q: got %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestForgetWorkerCommandRequiresConfirmationAndReportsUnverified(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "api.key")
	if err := os.WriteFile(key, []byte("control-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/sandboxd/workers/linux-1/forget" ||
			r.Header.Get("X-API-Key") != "control-secret" || string(body) != `{"confirm":true}` {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"workerID":"linux-1","unverified":["sandboxd-00000000000000000000000000000001"]}`)
	}))
	defer server.Close()
	var out bytes.Buffer
	if err := forgetWorker(context.Background(), []string{"-id", "linux-1", "-api-url", server.URL, "-api-key-file", key}, &out); err == nil || calls != 0 {
		t.Fatalf("forget without -confirm: %v, %d calls", err, calls)
	}
	if err := forgetWorker(context.Background(), []string{"-id", "linux-1", "-confirm", "-api-url", "http://100.64.0.1:43180", "-api-key-file", key}, &out); err == nil {
		t.Fatal("sent the API key over cleartext to a non-loopback host")
	}
	err := forgetWorker(context.Background(), []string{"-id", "linux-1", "-confirm", "-api-url", server.URL, "-api-key-file", key}, &out)
	if err != nil || calls != 1 || !strings.Contains(out.String(), "NOT proven gone") ||
		!strings.Contains(out.String(), "sandboxd-00000000000000000000000000000001") {
		t.Fatalf("forget-worker: %v, %d calls, output %q", err, calls, out.String())
	}
}
