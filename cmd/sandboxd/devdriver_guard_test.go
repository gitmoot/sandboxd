package main

import (
	"go/build/constraint"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const devDriverTag = "sandboxd_devdriver"

// The CI-only devvm driver has no isolation. It must stay behind its build tag
// and must never be linked into a production binary, even if a build sets the
// tag by mistake.
func TestProductionBinariesNeverLinkTheDevDriver(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	for _, tags := range []string{"", devDriverTag} {
		for _, goos := range []string{"linux", "darwin"} {
			command := exec.Command(goTool, "list", "-deps", "-tags", tags, "../sandboxd", "../sandboxd-pf-helper")
			command.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("go list (tags=%q GOOS=%s): %v\n%s", tags, goos, err, output)
			}
			for _, dep := range strings.Fields(string(output)) {
				if strings.HasSuffix(dep, "/internal/vm/devvm") || strings.HasSuffix(dep, "/cmd/sandboxd-dev") {
					t.Fatalf("production binary depends on %s (tags=%q GOOS=%s)", dep, tags, goos)
				}
			}
		}
	}
}

func TestDevDriverSourcesRequireTheBuildTag(t *testing.T) {
	var files []string
	for _, dir := range []string{"../../internal/vm/devvm", "../sandboxd-dev"} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 0 {
			t.Fatalf("no Go sources in %s", dir)
		}
		files = append(files, matches...)
	}
	for _, file := range files {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		first, _, _ := strings.Cut(string(source), "\n")
		expr, err := constraint.Parse(first)
		if err != nil {
			t.Fatalf("%s: first line %q is not a build constraint", file, first)
		}
		if expr.Eval(func(tag string) bool { return tag != devDriverTag }) {
			t.Fatalf("%s builds without the %s tag (constraint %q)", file, devDriverTag, first)
		}
	}
}
