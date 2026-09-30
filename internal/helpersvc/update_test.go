package helpersvc

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

type tarEntry struct {
	name, body string
	typ        byte
}

func releaseArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: typ}
		if typ != tar.TypeReg {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func goodEntries() []tarEntry {
	return []tarEntry{
		{name: "sandboxd", body: "new sandboxd binary"},
		{name: "sandboxd-pf-helper", body: "new helper binary"},
	}
}

// fakeGitHub serves one release the way GitHub does: the API's release JSON,
// and the assets under /download/<tag>/.
type fakeGitHub struct {
	tag, author string
	archive     []byte
	sums        string // SHA256SUMS; empty: computed from archive
	assetBase   string // overrides the assets' download base
	downloads   int
	requests    int
}

// installedMac is a Mac on which install already ran (v0.6.0), serving
// updates from f.
func installedMac(t *testing.T, f *fakeGitHub) *fakeMac {
	t.Helper()
	m := newFakeMac(t)
	if err := m.install(InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	m.out.Reset()
	m.launchd = nil
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests++
		base := "http://" + r.Host
		archiveName := "sandboxd-" + f.tag + "-darwin-arm64.tar.gz"
		switch r.URL.Path {
		case "/api/releases/latest", "/api/releases/tags/" + f.tag:
			assetBase := base + "/download/" + f.tag + "/"
			if f.assetBase != "" {
				assetBase = f.assetBase
			}
			json.NewEncoder(w).Encode(map[string]any{
				"tag_name": f.tag, "author": map[string]string{"login": f.author},
				"assets": []map[string]string{
					{"name": "SHA256SUMS", "browser_download_url": assetBase + "SHA256SUMS"},
					{"name": archiveName, "browser_download_url": assetBase + archiveName},
				},
			})
		case "/download/" + f.tag + "/SHA256SUMS":
			f.downloads++
			sums := f.sums
			if sums == "" {
				sums = fmt.Sprintf("%x  %s\n", sha256.Sum256(f.archive), archiveName)
			}
			io.WriteString(w, sums)
		case "/download/" + f.tag + "/" + archiveName:
			f.downloads++
			w.Write(f.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	m.host.HTTP = srv.Client()
	m.host.ReleasesAPI = srv.URL + "/api/releases"
	m.host.DownloadBase = srv.URL + "/download/"
	return m
}

func (m *fakeMac) update(want, version string) error {
	return m.host.Update(m.t.Context(), want, version)
}

// updated reports whether the release's binaries replaced the installed ones.
func (m *fakeMac) updated() bool {
	m.t.Helper()
	helper, sandboxd := m.read("usr/local/libexec/sandboxd-pf-helper"), m.read("usr/local/libexec/sandboxd")
	switch {
	case helper == "helper v1" && sandboxd == "sandboxd v1":
		if len(m.launchd) != 0 {
			m.t.Fatalf("launchctl %q ran without an update", m.launchd)
		}
		return false
	case helper == "new helper binary" && sandboxd == "new sandboxd binary":
		return true
	}
	m.t.Fatalf("half an update: helper %q, sandboxd %q", helper, sandboxd)
	return false
}

func TestUpdateInstallsTheVerifiedReleaseAndRestartsTheService(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	m.calls = nil
	if err := m.update("", "v0.6.0"); err != nil {
		t.Fatalf("%v\n%s", err, m.out.String())
	}
	if !m.updated() {
		t.Fatal("not updated")
	}
	if want := []string{"kickstart -k system/" + Label}; !reflect.DeepEqual(m.launchd, want) {
		t.Fatalf("launchctl %q, want %q", m.launchd, want)
	}
	if want := "as 501:20 /Users/jerry: " + testCLI + " list --all --format json"; !reflect.DeepEqual(m.calls[:1], []string{want}) {
		t.Fatalf("guest check %q, want %q first", m.calls, want)
	}
	for _, s := range []string{"v0.6.0 -> v0.7.0", "matches the release page"} {
		if !strings.Contains(m.out.String(), s) {
			t.Fatalf("output lacks %q:\n%s", s, m.out.String())
		}
	}
	if left, _ := os.ReadDir(m.path("usr/local/libexec")); len(left) != 2 {
		t.Fatalf("libexec holds %v, want the two binaries", left)
	}
}

func TestUpdateRefusesAnArchiveThatDoesNotMatchSHA256SUMS(t *testing.T) {
	good := releaseArchive(t, goodEntries())
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]",
		archive: releaseArchive(t, []tarEntry{{name: "sandboxd", body: "evil"}, {name: "sandboxd-pf-helper", body: "evil"}}),
		sums:    fmt.Sprintf("%x  sandboxd-v0.7.0-darwin-arm64.tar.gz\n", sha256.Sum256(good))}
	m := installedMac(t, f)
	if err := m.update("", "v0.6.0"); err == nil || m.updated() {
		t.Fatalf("a tampered archive was installed: %v", err)
	}
}

func TestUpdateRefusesAReleaseNotPublishedByTheWorkflow(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "someone", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	if err := m.update("", "v0.6.0"); err == nil || m.updated() || f.downloads != 0 {
		t.Fatalf("a hand-made release went ahead (downloads %d): %v", f.downloads, err)
	}
}

func TestUpdateRefusesReleasesOtherThanAskedFor(t *testing.T) {
	for _, tc := range []struct {
		rel  githubRelease
		want string
	}{
		{githubRelease{TagName: "v0.7.0", Draft: true}, ""},
		{githubRelease{TagName: "v0.7.0", Prerelease: true}, ""},
		{githubRelease{TagName: "v0.7.0-rc1"}, ""},
		{githubRelease{TagName: "v0.8.0"}, "v0.7.0"},
	} {
		tc.rel.Author.Login = releaseAuthor
		if err := checkRelease(tc.rel, tc.want); err == nil {
			t.Fatalf("accepted %+v for %q", tc.rel, tc.want)
		}
	}
}

func TestUpdateReadsOnlyValidSHA256SUMSLines(t *testing.T) {
	name := "sandboxd-v0.7.0-darwin-arm64.tar.gz"
	good := strings.Repeat("ab", 32)
	for sums, want := range map[string]string{
		good + "  " + name + "\n":                           good,
		strings.ToUpper(good) + " *" + name + "\n":          good,
		good[:62] + "  " + name + "\n":                      "",
		strings.Repeat("zz", 32) + "  " + name + "\n":       "",
		good + "  other.tar.gz\n":                           "",
		good + "  " + name + " extra\n":                     "",
		strings.Repeat("0", 64) + "  ../" + name + "\n":     "",
		good[:62] + "  " + name + "\n" + good + "  " + name: "",
	} {
		got, err := sumFor([]byte(sums), name)
		if got != want || (err == nil) != (want != "") {
			t.Fatalf("sumFor(%q) = %q, %v; want %q", sums, got, err, want)
		}
	}
}

func TestUpdateRefusesOversizedDownloadsAndEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "12345") }))
	t.Cleanup(srv.Close)
	h := &Host{HTTP: srv.Client()}
	if _, err := h.download(srv.URL, 4); err == nil {
		t.Fatal("a 5-byte body passed a 4-byte limit")
	}
	if body, err := h.download(srv.URL, 5); err != nil || string(body) != "12345" {
		t.Fatalf("5-byte limit: %q, %v", body, err)
	}

	old := releaseFiles["sandboxd"]
	releaseFiles["sandboxd"] = 5
	t.Cleanup(func() { releaseFiles["sandboxd"] = old })
	if _, err := unpackRelease(releaseArchive(t, []tarEntry{{name: "sandboxd", body: "123456"}, {name: "sandboxd-pf-helper", body: "x"}})); err == nil {
		t.Fatal("an entry over its limit was unpacked")
	}
	if _, err := unpackRelease(releaseArchive(t, []tarEntry{{name: "sandboxd", body: "12345"}, {name: "sandboxd-pf-helper", body: "x"}})); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRefusesAssetsOutsideTheRelease(t *testing.T) {
	archive := releaseArchive(t, goodEntries())
	// Another host serving a self-consistent archive and SHA256SUMS: only the
	// asset location check stands between it and the install.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
			fmt.Fprintf(w, "%x  sandboxd-v0.7.0-darwin-arm64.tar.gz\n", sha256.Sum256(archive))
			return
		}
		w.Write(archive)
	}))
	t.Cleanup(other.Close)
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: archive, assetBase: other.URL + "/v0.7.0/"}
	m := installedMac(t, f)
	if err := m.update("", "v0.6.0"); err == nil || m.updated() {
		t.Fatalf("assets from another host were installed: %v", err)
	}
}

func TestUpdateRefusesAssetURLsThatLeaveTheRelease(t *testing.T) {
	for _, suffix := range []string{"../v0.6.0/", "%2e%2e/v0.6.0/", "x/../"} {
		t.Run(suffix, func(t *testing.T) {
			f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
			m := installedMac(t, f)
			f.assetBase = m.host.DownloadBase + "v0.7.0/" + suffix
			if err := m.update("", "v0.6.0"); err == nil || f.downloads != 0 || m.updated() {
				t.Fatalf("asset URL with %q was fetched (downloads %d): %v", suffix, f.downloads, err)
			}
		})
	}
}

func TestUpdateRefusesArchivesWithAnythingButTheReleaseFiles(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"path traversal":     append(goodEntries(), tarEntry{name: "../sandboxd", body: "x"}),
		"nested path":        append(goodEntries(), tarEntry{name: "sub/sandboxd", body: "x"}),
		"unknown file":       append(goodEntries(), tarEntry{name: "evil.sh", body: "x"}),
		"empty unknown file": append(goodEntries(), tarEntry{name: "evil.sh"}),
		"symlink":            {{name: "sandboxd", typ: tar.TypeSymlink}, {name: "sandboxd-pf-helper", body: "x"}},
		"hard link":          {{name: "sandboxd", body: "x"}, {name: "sandboxd-pf-helper", typ: tar.TypeLink}},
		"duplicate":          append(goodEntries(), tarEntry{name: "sandboxd-pf-helper", body: "second"}),
		"no helper":          goodEntries()[:1],
		"no sandboxd":        goodEntries()[1:],
		"directory entry":    append([]tarEntry{{name: "sandboxd", typ: tar.TypeDir}}, goodEntries()[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, entries)}
			m := installedMac(t, f)
			if err := m.update("", "v0.6.0"); err == nil || m.updated() {
				t.Fatalf("installed: %v", err)
			}
		})
	}
}

func TestUpdateSkipsTheCurrentReleaseUnlessAskedForIt(t *testing.T) {
	f := &fakeGitHub{tag: "v0.6.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	if err := m.update("", "v0.6.0"); err != nil || m.updated() || !strings.Contains(m.out.String(), "already up to date") {
		t.Fatalf("latest == current: %v\n%s", err, m.out.String())
	}
	if err := m.update("v0.6.0", "v0.6.0"); err != nil || !m.updated() {
		t.Fatalf("--version v0.6.0 must reinstall: %v", err)
	}
}

// GitHub's "latest" is the most recently published release, so a patch to an
// older line published after a newer release must not silently downgrade.
func TestUpdateDoesNotDowngradeToAnOlderLatestUnlessAsked(t *testing.T) {
	f := &fakeGitHub{tag: "v0.5.9", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	if err := m.update("", "v0.10.0"); err == nil || m.updated() || !strings.Contains(err.Error(), "--version v0.5.9") {
		t.Fatalf("latest v0.5.9 over installed v0.10.0: %v", err)
	}
	if err := m.update("v0.5.9", "v0.10.0"); err != nil || !m.updated() {
		t.Fatalf("an explicit --version must go back: %v", err)
	}
}

func TestUpdateFromADevBuildInstallsTheLatest(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	if err := m.update("", "dev"); err != nil || !m.updated() {
		t.Fatalf("dev build: %v", err)
	}
}

func TestUpdateRefusesAMalformedVersion(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	for _, want := range []string{"0.7.0", "v0.7", "v0.7.0/../../x", "latest"} {
		if err := m.update(want, "v0.6.0"); err == nil || m.updated() || f.requests != 0 {
			t.Fatalf("--version %q: %d requests: %v", want, f.requests, err)
		}
	}
}

func TestUpdateNeedsRootOnTheMac(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	m.host.EUID = func() int { return 501 }
	if err := m.update("", "v0.6.0"); err == nil || m.updated() || !strings.Contains(err.Error(), "sudo") {
		t.Fatalf("non-root update: %v", err)
	}
}

func TestUpdateNeedsTheInstalledService(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	os.Remove(m.host.plistPath())
	if err := m.update("", "v0.6.0"); err == nil || !strings.Contains(err.Error(), "install") || m.updated() || f.downloads != 0 {
		t.Fatalf("update without the service: %v", err)
	}
}

func TestUpdateRefusesWhileAGuestRuns(t *testing.T) {
	vm := func(id, state string) string {
		return fmt.Sprintf(`{"configuration":{"id":%q},"status":{"state":%q}}`, id, state)
	}
	pins := vm("sandboxd-pin-0123456789abcdef", "running")
	for name, tc := range map[string]struct {
		containers string
		refuse     bool
	}{
		"guest running":         {"[" + pins + "," + vm("sandboxd-3f2a", "running") + "]", true},
		"inventory unavailable": {"", true},
		"inventory malformed":   {"null", true},
		"only pins":             {"[" + pins + "]", false},
		"guest stopped":         {"[" + pins + "," + vm("sandboxd-3f2a", "stopped") + "]", false},
		"other VM running":      {"[" + pins + "," + vm("buildkit", "running") + "]", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
			m := installedMac(t, f)
			m.containers = tc.containers
			err := m.update("", "v0.6.0")
			if tc.refuse && (err == nil || m.updated()) {
				t.Fatalf("updated under a guest: %v", err)
			}
			if !tc.refuse && (err != nil || !m.updated()) {
				t.Fatalf("no guest, but: %v", err)
			}
		})
	}
}

func TestUpdateRefusesAnUntrustedLibexec(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	os.Chmod(m.path("usr/local"), 0o777)
	if err := m.update("", "v0.6.0"); err == nil || m.updated() {
		t.Fatalf("updated into a writable tree: %v", err)
	}
}

func TestUpdateFailsWhenTheRestartedHelperNeverOpensItsSocket(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	m := installedMac(t, f)
	m.neverUp = true
	if err := m.update("", "v0.6.0"); err == nil || !strings.Contains(err.Error(), "sandboxd-pf-helper.log") {
		t.Fatalf("update with a dead helper: %v", err)
	}
}
