package control

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gitmoot/sandboxd/internal/vm"
)

// Profile selects the API surface and semantics a template's sandboxes get.
// Profiles are recorded per sandbox row and never mixed.
type Profile string

const (
	// ProfileStrict is the pinned Gitmoot subset, byte for byte: v1 create
	// with owner metadata, envdVersion "sandboxd-1", plain-text errors.
	ProfileStrict Profile = "gitmoot-strict"
	// ProfileE2B is the general E2B SDK surface: v2 create and connect,
	// optional owner metadata, semver envdVersion, full metrics, JSON errors.
	ProfileE2B Profile = "e2b"
)

// envdPort is envd's guest port; it is never an exposed template port.
const envdPort = vm.EnvdPort

// strictEnvdVersion is what gitmoot-strict sandboxes have always reported.
const strictEnvdVersion = "sandboxd-1"

// Template is one operator-registered template (CLI or configuration only;
// clients name a template, never an image). Clients may create it by its ID
// or any alias; the ledger records the ID.
type Template struct {
	// Arch is the guest architecture the template requires; a worker serves
	// it only on that architecture. "" means the local worker's.
	Arch string
	// Image, when set, is the image the gateway's local worker (or a
	// -worker-key-file worker) serves the template from. Enrolled workers
	// declare their own image for it.
	Image string
	// Profile is gitmoot-strict when empty.
	Profile Profile
	Aliases []string
	// EnvdVersion is the semantic version e2b-profile sandboxes report; the
	// SDKs gate features on it. Strict templates leave it empty.
	EnvdVersion string
	// Ports are the guest TCP ports (never envd's) clients may reach through
	// the gateway, with the sandbox's traffic or envd access token. No other
	// guest port is reachable. e2b templates only.
	Ports []int
	// StartCmd, when set, runs once per sandbox as root through envd right
	// after envd's /init, in the background (E2B runs it at template build
	// time and snapshots the result; sandboxd has no snapshots). ReadyCmd,
	// when set, is then run as root until it exits 0 before the create
	// returns. e2b templates only.
	StartCmd, ReadyCmd string
}

// entry is a registered template with its ID.
type entry struct {
	Template
	ID string
}

var (
	templateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	semver       = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	// errNoTokenSecret reports e2b templates without the envd token secret.
	errNoTokenSecret = errors.New("e2b templates need a token secret of at least 32 bytes")
)

// registry resolves template names and aliases. It is immutable after Open.
type registry struct {
	byName map[string]*entry // ID or alias -> template
	byID   map[string]*entry
	// e2b is set when any e2b-profile template is registered. Without one,
	// every response is byte-for-byte what the strict-only service returned.
	e2b bool
}

// newRegistry admits the local worker's primary strict template (primaryID
// is "" for a gateway without a local driver) and the further registered
// ones. localArch is the local worker's architecture, "" without one.
func newRegistry(primaryID, primaryImage, localArch string, extra map[string]Template) (*registry, error) {
	r := &registry{byName: make(map[string]*entry), byID: make(map[string]*entry)}
	add := func(id string, template Template) error {
		registered := &entry{ID: id, Template: template}
		for _, name := range append([]string{id}, template.Aliases...) {
			if _, taken := r.byName[name]; taken {
				return fmt.Errorf("template name or alias %q is registered twice", name)
			}
			r.byName[name] = registered
		}
		r.byID[id] = registered
		r.e2b = r.e2b || template.Profile == ProfileE2B
		return nil
	}
	if primaryID != "" {
		if err := add(primaryID, Template{Arch: localArch, Image: primaryImage, Profile: ProfileStrict}); err != nil {
			return nil, err
		}
	}
	for _, id := range slices.Sorted(maps.Keys(extra)) {
		template := extra[id]
		template.Aliases = slices.Clone(template.Aliases)
		template.Ports = slices.Clone(template.Ports)
		if template.Profile == "" {
			template.Profile = ProfileStrict
		}
		if template.Arch == "" {
			template.Arch = localArch
		}
		if err := template.validate(id); err != nil {
			return nil, err
		}
		if template.Arch == "" {
			return nil, fmt.Errorf("template %q needs an architecture: the gateway has no local worker", id)
		}
		if template.Image != "" && template.Arch != localArch {
			return nil, fmt.Errorf("template %q has an image for the local worker, which runs %q, but requires %s", id, localArch, template.Arch)
		}
		if err := add(id, template); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// validate checks a template as registered; an empty Arch or Image is
// allowed here and resolved by newRegistry.
func (t Template) validate(id string) error {
	if !templateName.MatchString(id) {
		return fmt.Errorf("invalid template ID %q", id)
	}
	for _, alias := range t.Aliases {
		if !templateName.MatchString(alias) {
			return fmt.Errorf("invalid alias %q for template %q", alias, id)
		}
	}
	if t.Arch != "" && !validArch(t.Arch) {
		return fmt.Errorf("template %q must name an arm64 or amd64 architecture", id)
	}
	if t.Image != "" && (t.Image[0] == '-' || strings.IndexFunc(t.Image, func(r rune) bool { return r <= ' ' || r == 0x7f || r == ',' }) >= 0) {
		return fmt.Errorf("invalid image %q for template %q", t.Image, id)
	}
	switch t.Profile {
	case ProfileStrict, "":
		if t.EnvdVersion != "" {
			return fmt.Errorf("gitmoot-strict template %q always reports envd %s; drop envd-version", id, strictEnvdVersion)
		}
		if len(t.Ports) > 0 || t.StartCmd != "" || t.ReadyCmd != "" {
			return fmt.Errorf("gitmoot-strict template %q cannot expose ports or run start/ready commands", id)
		}
	case ProfileE2B:
		match := semver.FindStringSubmatch(t.EnvdVersion)
		if match == nil {
			return fmt.Errorf("e2b template %q needs envd-version MAJOR.MINOR.PATCH, got %q", id, t.EnvdVersion)
		}
		// The SDKs kill a fresh sandbox reporting envd older than 0.1.0.
		if match[1] == "0" && match[2] == "0" {
			return fmt.Errorf("e2b template %q: envd-version must be at least 0.1.0", id)
		}
		seen := make(map[int]bool)
		for _, port := range t.Ports {
			if port < 1 || port > 65535 || port == envdPort || seen[port] {
				return fmt.Errorf("e2b template %q: port %d must be 1-65535, not envd's %d, and listed once", id, port, envdPort)
			}
			seen[port] = true
		}
		for name, command := range map[string]string{"start-cmd": t.StartCmd, "ready-cmd": t.ReadyCmd} {
			if strings.ContainsFunc(command, func(r rune) bool { return r < ' ' || r == 0x7f }) || len(command) > 4096 {
				return fmt.Errorf("e2b template %q: invalid %s", id, name)
			}
		}
	default:
		return fmt.Errorf("template %q: profile must be %q or %q, got %q", id, ProfileStrict, ProfileE2B, t.Profile)
	}
	return nil
}

// lookup resolves a client-supplied template ID or alias.
func (r *registry) lookup(name string) (*entry, bool) {
	template, ok := r.byName[name]
	return template, ok
}

// sharedProfile is the error format of responses not tied to one sandbox
// (authentication, list, unknown IDs): JSON once an e2b template is
// registered, the original plain text otherwise.
func (r *registry) sharedProfile() Profile {
	if r.e2b {
		return ProfileE2B
	}
	return ProfileStrict
}

// rowProfile maps a ledger row's profile; rows from before profiles were
// recorded are all gitmoot-strict.
func rowProfile(profile string) Profile {
	if profile == "" {
		return ProfileStrict
	}
	return Profile(profile)
}

// ParseTemplate parses one operator registration:
//
//	id=<id>[,arch=arm64|amd64][,image=<ref>][,profile=gitmoot-strict|e2b][,alias=<name>]...[,envd-version=X.Y.Z]
//	  [,port=<n>]...[,start-cmd=<command>][,ready-cmd=<command>]
//
// The profile defaults to gitmoot-strict and the architecture to the local
// worker's. Without an image only enrolled workers can serve the template.
// With a non-empty fixedImage (a driver with a single image) the image key
// may be omitted and must otherwise equal it. Ports and commands are e2b
// only; commands cannot contain commas.
func ParseTemplate(spec, fixedImage string) (string, Template, error) {
	var id string
	template := Template{Image: fixedImage}
	seen := make(map[string]bool)
	for _, field := range strings.Split(spec, ",") {
		key, value, ok := strings.Cut(field, "=")
		if !ok || value == "" {
			return "", Template{}, fmt.Errorf("template field %q is not key=value", field)
		}
		if key != "alias" && key != "port" && seen[key] {
			return "", Template{}, fmt.Errorf("template field %q repeated", key)
		}
		seen[key] = true
		switch key {
		case "id":
			id = value
		case "alias":
			template.Aliases = append(template.Aliases, value)
		case "image":
			if fixedImage != "" && value != fixedImage {
				return "", Template{}, fmt.Errorf("image must be %q with this driver", fixedImage)
			}
			template.Image = value
		case "arch":
			template.Arch = value
		case "profile":
			template.Profile = Profile(value)
		case "envd-version":
			template.EnvdVersion = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil || strconv.Itoa(port) != value {
				return "", Template{}, fmt.Errorf("template port %q is not a number", value)
			}
			template.Ports = append(template.Ports, port)
		case "start-cmd":
			template.StartCmd = value
		case "ready-cmd":
			template.ReadyCmd = value
		default:
			return "", Template{}, fmt.Errorf("unknown template field %q", key)
		}
	}
	if err := template.validate(id); err != nil {
		return "", Template{}, err
	}
	return id, template, nil
}

// TemplateFlags is a repeatable -register-template flag.
type TemplateFlags struct {
	Templates map[string]Template
	// FixedImage is the driver's only image, if it has just one.
	FixedImage string
}

func (f *TemplateFlags) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(slices.Sorted(maps.Keys(f.Templates)), " ")
}

func (f *TemplateFlags) Set(value string) error {
	id, template, err := ParseTemplate(value, f.FixedImage)
	if err != nil {
		return err
	}
	if _, taken := f.Templates[id]; taken {
		return fmt.Errorf("template %q is registered twice", id)
	}
	if f.Templates == nil {
		f.Templates = make(map[string]Template)
	}
	f.Templates[id] = template
	return nil
}

// Declared is a worker's template declaration: the primary template and
// every registered template that has an image, mapped to that image.
func Declared(primaryID, primaryImage string, templates map[string]Template) map[string]string {
	declared := map[string]string{primaryID: primaryImage}
	for id, template := range templates {
		if template.Image != "" {
			declared[id] = template.Image
		}
	}
	return declared
}

// Images lists every image a worker may start, primary first; drivers use it
// as their image allowlist.
func Images(primaryImage string, templates map[string]Template) []string {
	images := []string{primaryImage}
	for _, id := range slices.Sorted(maps.Keys(templates)) {
		if image := templates[id].Image; image != "" && !slices.Contains(images, image) {
			images = append(images, image)
		}
	}
	return images
}

// ReadTokenSecret reads the envd token secret: a regular file readable only
// by its owner, holding at least 32 bytes. Rotating it invalidates the envd
// tokens of every live e2b-profile sandbox.
func ReadTokenSecret(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("token secret must be in a regular 0600 file")
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token secret: %w", err)
	}
	if len(bytes.TrimSpace(secret)) < 32 {
		return nil, errNoTokenSecret
	}
	return secret, nil
}
