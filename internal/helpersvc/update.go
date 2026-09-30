package helpersvc

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// The update trusts what the owner checks by hand on first install: the
// release page on github.com and its SHA256SUMS, fetched from GitHub itself,
// never from the agents' server. The publisher check proves only that a
// GitHub Actions token in this repo published the release, not that
// release.yml (which builds only tags on main) did: a workflow merged into
// main could publish one too. That is no wider than a merge that changes
// release.yml itself.
const releaseAuthor = "github-actions[bot]"

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// releaseFiles are the only entries a release archive may hold, each a
// regular file at the top level no larger than its limit; all are required.
var releaseFiles = map[string]int64{
	"sandboxd":           200 << 20,
	"sandboxd-pf-helper": 200 << 20,
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Author     struct {
		Login string `json:"login"`
	} `json:"author"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Update installs the latest release (or want, e.g. "v0.6.0" to go back)
// over the installed service and restarts it. version is the running
// (installed) helper's.
func (h *Host) Update(ctx context.Context, want, version string) error {
	if err := h.requireRootOnMac("update"); err != nil {
		return err
	}
	if want != "" && !releaseTag.MatchString(want) {
		return fmt.Errorf("--version %q: want a release tag like v0.7.0", want)
	}
	service, err := h.installedService()
	if err != nil {
		return err
	}
	url := h.ReleasesAPI + "/latest"
	if want != "" {
		url = h.ReleasesAPI + "/tags/" + want
	}
	var rel githubRelease
	if err := h.getJSON(url, &rel); err != nil {
		return err
	}
	if err := checkRelease(rel, want); err != nil {
		return err
	}
	if want == "" && releaseTag.MatchString(version) {
		switch c := compareTags(rel.TagName, version); {
		case c == 0:
			fmt.Fprintf(h.Stdout, "already up to date: %s\n", version)
			return nil
		case c < 0:
			// GitHub's "latest" is the most recently published release,
			// not the highest version.
			return fmt.Errorf("the latest release %s is older than the installed %s; nothing installed (to go back on purpose: --version %s)", rel.TagName, version, rel.TagName)
		}
	}
	archiveName := "sandboxd-" + rel.TagName + "-darwin-arm64.tar.gz"
	sumsURL, archiveURL, err := h.releaseAssets(rel, archiveName)
	if err != nil {
		return err
	}
	sums, err := h.download(sumsURL, 64<<10)
	if err != nil {
		return err
	}
	wantSum, err := sumFor(sums, archiveName)
	if err != nil {
		return err
	}
	archive, err := h.download(archiveURL, 400<<20)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != wantSum {
		return fmt.Errorf("%s: sha256 %x does not match the release's SHA256SUMS (%s); nothing installed", archiveName, got, wantSum)
	}
	files, err := unpackRelease(archive)
	if err != nil {
		return err
	}
	fmt.Fprintf(h.Stdout, "%s sha256 %s (matches the release page)\n", archiveName, wantSum)

	if err := h.refuseRunningGuests(ctx, service); err != nil {
		return err
	}
	if err := h.trustedTree(h.Libexec); err != nil {
		return fmt.Errorf("refusing to install into %s: %w", h.Libexec, err)
	}
	if err := h.writeFile(h.sandboxdPath(), files["sandboxd"], 0o755); err != nil {
		return err
	}
	if err := h.writeFile(h.helperPath(), files["sandboxd-pf-helper"], 0o755); err != nil {
		return err
	}
	if err := h.launchctl(ctx, "kickstart", "-k", "system/"+Label); err != nil {
		return err
	}
	if err := h.waitSocket(service.socket); err != nil {
		return err
	}
	fmt.Fprintf(h.Stdout, "updated %s -> %s; restart sandboxd to run the new %s\n", version, rel.TagName, h.sandboxdPath())
	return nil
}

// installedService is what the installed launchd job runs.
type installedService struct {
	worker Cred
	cli    string
	socket string
}

func (h *Host) installedService() (installedService, error) {
	data, err := os.ReadFile(h.plistPath())
	if os.IsNotExist(err) {
		return installedService{}, fmt.Errorf("%s is not installed; first install it: sudo ./sandboxd-pf-helper install", Label)
	}
	if err != nil {
		return installedService{}, err
	}
	args, err := programArguments(data)
	if err != nil {
		return installedService{}, err
	}
	var s installedService
	values := map[string]*string{"--container-cli": &s.cli, "--socket": &s.socket, "--worker-home": &s.worker.Home}
	for name, into := range values {
		if *into, err = flagValue(args, name); err != nil {
			return installedService{}, err
		}
	}
	for name, into := range map[string]*int{"--worker-uid": &s.worker.UID, "--worker-gid": &s.worker.GID} {
		text, err := flagValue(args, name)
		if err != nil {
			return installedService{}, err
		}
		if *into, err = strconv.Atoi(text); err != nil {
			return installedService{}, fmt.Errorf("launchd plist: %s %q", name, text)
		}
	}
	return s, nil
}

// refuseRunningGuests refuses while a sandboxd guest VM runs: restarting the
// helper fails sandboxd's firewall gate, which stops guests mid-job.
func (h *Host) refuseRunningGuests(ctx context.Context, s installedService) error {
	out, err := h.Run(ctx, &s.worker, s.cli, "list", "--all", "--format", "json")
	if err != nil {
		return fmt.Errorf("cannot list VMs to check no guest is running; nothing installed: %w", err)
	}
	var items []struct {
		Configuration struct {
			ID string `json:"id"`
		} `json:"configuration"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &items); err != nil || items == nil {
		return fmt.Errorf("incomplete Apple container inventory; nothing installed: %v", err)
	}
	var running []string
	for _, item := range items {
		id := item.Configuration.ID
		if strings.HasPrefix(id, "sandboxd-") && !strings.HasPrefix(id, "sandboxd-pin-") && item.Status.State == "running" {
			running = append(running, id)
		}
	}
	if len(running) > 0 {
		return fmt.Errorf("sandboxd guest VMs are running (%s); update once they finish; nothing installed", strings.Join(running, ", "))
	}
	return nil
}

func checkRelease(rel githubRelease, want string) error {
	switch {
	case !releaseTag.MatchString(rel.TagName):
		return fmt.Errorf("release tag %q is not a version tag", rel.TagName)
	case want != "" && rel.TagName != want:
		return fmt.Errorf("asked for %s, GitHub returned %s", want, rel.TagName)
	case rel.Draft || rel.Prerelease:
		return fmt.Errorf("release %s is a draft or pre-release", rel.TagName)
	case rel.Author.Login != releaseAuthor:
		return fmt.Errorf("release %s was published by %q, not the release workflow (%s); nothing installed", rel.TagName, rel.Author.Login, releaseAuthor)
	}
	return nil
}

// releaseAssets returns the download URLs of SHA256SUMS and the archive. Each
// must be exactly <DownloadBase><tag>/<name>, the address GitHub gives this
// release's assets; anything else (another host, another release, a ../) is
// refused.
func (h *Host) releaseAssets(rel githubRelease, archiveName string) (sums, archive string, err error) {
	base := h.DownloadBase + rel.TagName + "/"
	found := map[string]bool{}
	for _, a := range rel.Assets {
		if a.Name != "SHA256SUMS" && a.Name != archiveName {
			continue
		}
		if a.URL != base+a.Name {
			return "", "", fmt.Errorf("asset %s is at %s, not %s", a.Name, a.URL, base+a.Name)
		}
		found[a.Name] = true
	}
	if !found["SHA256SUMS"] || !found[archiveName] {
		return "", "", fmt.Errorf("release %s lacks SHA256SUMS or %s", rel.TagName, archiveName)
	}
	return base + "SHA256SUMS", base + archiveName, nil
}

// compareTags compares two vX.Y.Z tags numerically: -1, 0 or 1.
func compareTags(a, b string) int {
	pa, pb := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := range 3 {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// sumFor finds name's sha256 in a sha256sum listing.
func sumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if len(f[0]) != 64 {
				break
			}
			if _, err := hex.DecodeString(f[0]); err != nil {
				break
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no valid line for %s", name)
}

// unpackRelease returns the archive's files. Anything but the known regular
// files at the top level, once each, is refused, and all must be present.
func unpackRelease(archive []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		limit, ok := releaseFiles[hdr.Name]
		if _, dup := files[hdr.Name]; !ok || hdr.Typeflag != tar.TypeReg || dup {
			return nil, fmt.Errorf("archive entry %q is not one of the release files; nothing installed", hdr.Name)
		}
		if hdr.Size > limit {
			return nil, fmt.Errorf("archive entry %s is too large", hdr.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, limit))
		if err != nil {
			return nil, err
		}
		files[hdr.Name] = body
	}
	for name := range releaseFiles {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("archive lacks %s; nothing installed", name)
		}
	}
	return files, nil
}

func (h *Host) getJSON(url string, v any) error {
	body, err := h.download(url, 1<<20)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}

func (h *Host) download(url string, limit int64) ([]byte, error) {
	resp, err := h.HTTP.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return body, nil
}
