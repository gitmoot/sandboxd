# Linux worker: Firecracker driver

`sandboxd -driver firecracker` runs each sandbox as a Firecracker microVM on
Linux/KVM (x86_64 only). It serves the same API as the Apple worker: the
Gitmoot review profile (`gitmoot-strict`) and, unlike the Apple worker, the
`e2b` profile that the stock E2B SDKs use. Tracking: [#29](https://github.com/gitmoot/sandboxd/issues/29).

## Isolation per VM

| Boundary | How |
| --- | --- |
| VM | One Firecracker microVM per sandbox, started by the jailer with `--new-pid-ns` |
| Host identity | Slot *i* runs its VMM as UID/GID `fc-uid-base + i` and its NAT as `fc-uid-base + 1000 + i`. Each VM gets its own chroot under `<fc-root>/jail/firecracker/<id>/root` |
| Limits | cgroup v2 `sbx-fc/<id>`: `memory.max` = guest RAM + 128 MiB, `memory.swap.max=0`, `cpu.max` = vCPUs × 100 ms per 100 ms, `pids.max=64`. Plus rlimits `fsize` (home disk size) and `nofile=256` |
| Disk | The root image is a hard link of a 0444 ext4 file, attached read-only. A fresh sparse `home.ext4` (`-fc-home-disk-mib`, default 10 GiB) is the only writable disk. The guest formats it at boot and mounts it on `/home/user`, owned by 1000:1000. `/tmp` and `/var/tmp` are bounded tmpfs |
| Exec and files | Over vsock only, through Firecracker's host-side Unix socket in the jail. The VMM owns that directory, so the daemon opens each path component beneath the root-owned jail directory with `O_NOFOLLOW`, requires the directory and socket to be owned by the VMM UID, and connects through the opened socket (`/proc/self/fd/N`), never through a re-resolved path. The guest agent (`cmd/sandboxd-guest-agent`, PID 1) runs every command and file write as uid/gid 1000 with no supplementary groups |
| Admission | `-fc-disk-floor-mib` (default 8 GiB): `Create` refuses when free disk on `fc-root` is below the floor plus one home disk |

CPU and memory come from `-cpus` and `-memory-mib`, the same flags the Apple
worker uses.

## Network: internet yes, private networks no

Each VM has its own network namespace `sbx-<id>`. It contains the VM's tap
`sbxvm0` (10.200.0.1/30, guest 10.200.0.2) and a user-mode NAT,
[slirp4netns](https://github.com/rootless-containers/slirp4netns), on tap
`sbxsl0`. Nothing in the namespace is bridged or routed to the host network,
and no host forwarding is used. Docker's `FORWARD DROP` policy, and every
Docker, Tailscale or iptables chain, stays untouched.

- **Namespace.** A user namespace that maps only the NAT UID owns the
  namespace. slirp4netns joins it as that UID with no host capabilities,
  using `--enable-sandbox --enable-seccomp --disable-host-loopback
  --disable-dns` (`--disable-host-loopback` is dropped only with
  `-fc-host-port`, below). The namespace table `inet sbx_vm` forwards only
  from `sbxvm0` to `sbxsl0`, and only to addresses outside the deny list. It
  rejects all traffic to the namespace itself (including the NAT's 10.0.2.2
  host alias and 10.0.2.3 resolver), and it masquerades.
- **Host.** All guest traffic leaves the host as sockets of the NAT UIDs.
  The sandboxd-owned table `inet sbx_fc` has one `output` hook. For those
  UIDs (`meta skuid`) it rejects every host-local, broadcast, multicast and
  anycast destination (`fib daddr type`, which covers all host interfaces:
  public, Docker bridges, Tailscale, loopback aliases). It also rejects
  `0/8, 10/8, 100.64/10, 127/8, 168.63.129.16/32 (Azure WireServer),
  169.254/16, 172.16/12, 192.168/16, 224/3` and
  `::/127, ::ffff:0:0/96, 64:ff9b::/96, fc00::/7, fe80::/10, ff00::/8`,
  plus every `-fc-deny-cidr`. All other sockets on the host are unaffected.
- **Other guests.** Every guest has the same private address in its own
  namespace, and no route to any other.
- **DNS.** The image's `/etc/resolv.conf` points at public resolvers
  (1.1.1.1, 8.8.8.8), reached through the NAT. The host resolver
  (127.0.0.53) is deliberately unreachable.
- **IPv6.** Disabled in the namespace; guests get IPv4 internet only.
- **Cloud metadata on public addresses.** Guests can reach the public
  internet. Metadata services on link-local addresses (169.254.169.254 on
  AWS, GCP, Azure IMDS and most others) and Azure's WireServer are denied
  above. If the deployment host runs on a cloud that serves metadata,
  credentials or other host-scoped services on a public address, list each
  one with a repeatable `-fc-deny-cidr <prefix>`. It is added to both the
  host and the namespace tables.

The daemon installs the table atomically before admitting guests (`Arm`),
re-checks it (`nft -s list table inet sbx_fc`) before every create, and
destroys the guest if it changed. While any command runs or any envd stream
is open, one monitor per daemon re-checks the table once a second for all of
them (commands and envd dials reuse its result from the last second). A
check that finds the table missing or changed destroys every watched guest at
once; a check that fails to complete (an `nft` error or timeout) is tolerated
once, and a second consecutive failure counts as a loss. On a clean
shutdown the daemon destroys every guest, then removes the table and the
cgroup parent.

### One host port (`-fc-host-port`)

Guests cannot reach the host, with one opt-in exception: `-fc-host-port
<port>` (default 0, none) lets every guest open TCP connections to
`10.0.2.2:<port>`, which is the host's `127.0.0.1:<port>`. It exists for a
host service the review agent must call, such as Gitmoot's credential
gateway (the model and GitHub credential broker): guests use
`https://10.0.2.2:<port>`, so that service's TLS certificate needs the IP
SAN `10.0.2.2`, and it must accept connections on loopback (from
127.0.0.1). It is one port, not a list: one broker per host is the only
use, and each extra port is one more host service reachable from untrusted
code.

What it changes, and nothing else:

- slirp4netns runs without `--disable-host-loopback`, so it connects to
  `127.0.0.1:<port>` as the NAT UID when the guest connects to
  `10.0.2.2:<port>`.
- `inet sbx_vm` gains, before the internet rule, `iifname "sbxvm0" oifname
  "sbxsl0" ip daddr 10.0.2.2 tcp dport <port> accept`. Every other port or
  protocol (UDP included) to 10.0.2.2 still hits the reject.
- `inet sbx_fc` gains, as the first rule of `chain guest`, `meta skuid
  <NAT UIDs> ip daddr 127.0.0.1 tcp dport <port> accept`. Only the NAT UIDs
  (base+1000 … base+1999), never the VMM UIDs, and only that address and
  port; other loopback ports, the host's other addresses (public, Docker,
  Tailscale) on any port including `<port>`, private ranges and other
  guests stay rejected.

The daemon refuses port 22 (SSH), its own `-listen` port and anything
outside 1–65535. It fails closed: `Arm` reads the host table back and fails
unless the exception is present exactly once, first in `chain guest`, and
no other accept rule exists (with no host port: no accept rule at all);
each create reads the namespace table back and fails unless the 10.0.2.2
rule is exactly as configured. The armed readback includes the exception,
so the per-create check and the once-a-second monitor treat any change to
it as a lost firewall. The real-KVM test `TestFirecrackerKVMHostPort` checks
that guests reach a host listener on the allowed port at 10.0.2.2 and not on
the host's own addresses, and that a second listener on another port, host
SSH, UDP to the alias and the rest of the deny list stay unreachable.

## Recovery

The driver keeps no in-memory state. Its inventory joins the ownership
records (`<fc-root>/run/<id>.json`), the jails, the `sbx-*` namespaces, and
the VMM and NAT cgroups. A VM is running only if all of them are present and
both cgroups have processes. Everything else is reported as stopped. A
foreign or malformed entry makes `List` fail rather than return an
incomplete inventory.

VMs survive a daemon crash or `kill -9`: their processes live in their own
cgroups, and the table outlives the daemon. On restart the daemon re-arms
the table. The control plane then keeps the VMs its ledger still owns and
destroys orphans and partial VMs through `Destroy`, which kills both
cgroups, deletes the namespace (and with it the tap), and removes the jail
and the record. `Destroy` is idempotent from any partial state.

## Install

Host prerequisites: an x86_64 host with `/dev/kvm`, cgroup v2 with
`cpu memory pids` enabled at the root, `nft`, `ip`, `nsenter`, `unshare`,
`setpriv` and `slirp4netns` (tested with 1.2.1), `curl`, plus Docker for
building the images. Run the commands below as root, from a checkout of the
same tag as the `sandboxd` binary: the guest agent in the images and the
daemon talk a private protocol, so build the images with the agent of that
release.

### From a release

Releases after v0.2.0 publish `sandboxd-<tag>-linux-amd64.tar.gz`
(`sandboxd` and `sandboxd-guest-agent`) and, for a gateway that runs no VMs
itself (`-driver none`), `sandboxd-<tag>-linux-arm64.tar.gz` (`sandboxd`
only), built by `.github/workflows/release.yml` with
`CGO_ENABLED=0 go build -trimpath`. The release page lists their SHA-256
in `SHA256SUMS`; compare it in your own browser before a first install.

```sh
tag=<tag>
git clone --branch "$tag" https://github.com/gitmoot/sandboxd && cd sandboxd
d=$(mktemp -d)
(cd "$d" && curl -fsSLO "https://github.com/gitmoot/sandboxd/releases/download/$tag/sandboxd-$tag-linux-amd64.tar.gz" \
  && curl -fsSLO "https://github.com/gitmoot/sandboxd/releases/download/$tag/SHA256SUMS" \
  && sha256sum -c --ignore-missing SHA256SUMS && tar -xzf "sandboxd-$tag-linux-amd64.tar.gz")
install -m 0755 "$d/sandboxd" /usr/local/bin/sandboxd
# The image build scripts take the release's guest agent instead of
# building one; then they need no Go toolchain.
export SANDBOXD_GUEST_AGENT="$d/sandboxd-guest-agent"
```

### From source

With Go 1.26 (`go.mod`), from the checkout:

```sh
CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/sandboxd ./cmd/sandboxd
```

Leave `SANDBOXD_GUEST_AGENT` unset; each image build script then builds
`cmd/sandboxd-guest-agent` itself (`GOTOOLCHAIN` defaults to go1.26.4).

### Firecracker, kernel and images (`/var/lib/sandboxd-fc`)

```sh
# Firecracker v1.17.0 + jailer and guest kernel 6.1.186, each SHA-256 pinned.
images/linux-amd64-fc/install-firecracker.sh /var/lib/sandboxd-fc
# Read-only review root image (debian:bookworm-slim by digest, git, bash, curl,
# gcc/g++/make, python3, user 1000, plus the guest agent). Prints the path,
# images/review-amd64-<sha256 prefix>.ext4, about 600 MB.
images/linux-amd64-fc/build.sh /var/lib/sandboxd-fc
# The same plus Go 1.26 and a module cache (below). Prints the path,
# images/review-go126-amd64-<sha256 prefix>.ext4, about 1 GB.
images/linux-amd64-fc/build.sh --go126 /var/lib/sandboxd-fc
```

| Path | Content |
| --- | --- |
| `bin/firecracker`, `bin/jailer` | v1.17.0 x86_64, release tarball SHA-256 `06094a11…de558` |
| `kernel/vmlinux-6.1.186` | Firecracker CI kernel, SHA-256 `ea0e55d0…f69c8` |
| `images/review-amd64-<sha>.ext4` | The read-only root image, with its `.sha256` |
| `images/review-go126-amd64-<sha>.ext4` | The read-only Go review image, with its `.sha256` |
| `jail/`, `run/` | Per-VM state, empty when no VM exists |

### Go review image (`--go126`)

The amd64 counterpart of the Mac's `review-go126` image
(`images/linux-arm64`): the review image above plus `/usr/local/go` copied
unchanged from the same `golang:1.26.4-bookworm` image index, pinned by
digest (Go 1.26.4, `go` and `gofmt` also in `/usr/local/bin`), and a
pre-filled module cache. The cache holds the full module graph of each
`GOMOD_REPOS` entry in the `Dockerfile` (`<clone URL>@<commit>`; currently
gitmoot/gitmoot at `8d58db9d…63e3265f9`), downloaded and verified at build
time exactly as `images/linux-arm64` does, about 75 MB. Bump the commit and
rebuild when a listed repository changes its `go.mod`.

Unlike the Mac image, guests here have internet access, so the cache is a
read-only module proxy, not the module cache itself. The image's
`/etc/sandboxd/env` sets `GOPROXY=file:///opt/gomodcache/cache/download,https://proxy.golang.org,direct`,
`GOMODCACHE=/home/user/go/pkg/mod`, `GOPATH=/home/user/go`,
`GOCACHE=/home/user/.cache/go-build`, `GOTOOLCHAIN=local` and
`GOFLAGS=-mod=readonly`, and puts `/home/user/go/bin` and
`/usr/local/go/bin` first on `PATH`. Cached modules are extracted onto the
guest's private home disk without network access; anything else comes from
the public proxy. Both are checked against the repository's `go.sum`, and
modules missing from it against the default checksum database.

`TestFirecrackerKVMGoImage` (`SANDBOXD_FC_KVM=1`; `SANDBOXD_FC_GO_IMAGE`
overrides the image) boots it, checks `go version`, `git` and the CA bundle,
builds a module without network access (`GOPROXY=off`), and builds a module
using gitmoot's dependency `gopkg.in/yaml.v3` with the image's cache as the
only proxy.

## E2B base image

Templates with `profile=e2b` use this image instead of the review image.
Build it like the review image (root, from the repository root):

```sh
# Prints the path, images/e2b-amd64-<sha256 prefix>.ext4, about 340 MB.
images/e2b-amd64-fc/build.sh /var/lib/sandboxd-fc
```

It is `debian:bookworm-slim` (same digest) with bash, ca-certificates, curl,
git, sudo, python3 (also as `python`), procps, iproute2, netbase, tar, gzip
and e2fsprogs; no compilers. User `user` (1000:1000, home `/home/user`,
shell bash) has passwordless sudo (`/etc/sudoers.d/user`). The guest agent is
still PID 1 (`/sbin/sandboxd-agent`); for e2b guests the driver adds the
kernel argument `sandboxd.envd=1` and the agent starts `/usr/bin/envd`.

`/usr/bin/envd` is upstream [E2B envd](https://github.com/e2b-dev/infra)
0.9.0, built from e2b-dev/infra commit `0c2108b1b76a66d18cf095d51fd7c51c703648ae`
(the release has no git tag). The script downloads E2B's release binary and
refuses any other SHA-256 than `c42a31d7…a02355`. envd is Apache-2.0; the
image carries its license and source note in `/usr/share/doc/envd/`
(`LICENSE`, `SOURCE`).

`images/e2b-arm64` is the same image for the Apple driver (linux/arm64,
envd arm64 SHA-256 `bf346976…d89189`), with envd as its entrypoint; the
build command is in its header.

### Root inside an e2b guest

An `e2b` guest boots the same way, then the agent formats the per-VM disk,
mounts an overlay of the read-only image (lower) and that disk (upper) and
`pivot_root`s into it, so the root filesystem is writable and private to the
VM; the image file itself is attached read-only and never changes. envd runs
as root and starts commands as `user` or, when the SDK asks, `root`.

Root inside the guest can do anything to *that VM*: write any file of its
overlay root, change the guest's network configuration, kill the agent or
envd (which ends the VM: the agent halts it), load nothing (the kernel has no
modules) and use only the two virtio disks attached to it (`/dev/vda` is
read-only at the VMM). It cannot leave the VM: the boundary is KVM plus the
jailed, unprivileged Firecracker process, the guest has no shared host
filesystem and no host-side vsock listener (guest-initiated vsock connections
are reset), and its only network path is the NAT confined by the host and
namespace tables above, which it cannot change from inside. The probes in
[#25](https://github.com/gitmoot/sandboxd/issues/25) ran as root in a real
guest: host addresses on every interface, Docker bridges, Tailscale and
ZeroTier, the NAT's own host and resolver, metadata and RFC 1918 addresses
were unreachable, vsock to the host was refused, and the internet was
reachable.

## Code-interpreter image

The image of the `code-interpreter-v1` template: E2B's
[code-interpreter](https://github.com/e2b-dev/code-interpreter) template
(Jupyter Server, the FastAPI code-interpreter server on port 49999 and the
python, javascript, r, java and bash kernels) on top of the e2b guest
contract above (guest agent as PID 1, envd 0.9.0, `/etc/sandboxd/env`, user
`user` 1000:1000 with passwordless sudo). Build it like the others (root,
from the repository root; about 11 minutes uncached):

```sh
# Prints the path, images/code-interpreter-amd64-<sha256 prefix>.ext4,
# about 3.6 GiB (3.4 GiB allocated).
images/code-interpreter-amd64-fc/build.sh /var/lib/sandboxd-fc
```

`build.sh` downloads upstream's `template/` from GitHub at
`@e2b/code-interpreter-template@0.4.6` (commit
`8d51873ccf620498347210dc3ec9698cf67c2829`, codeload archive SHA-256
`0a03c6b0…eb130ca`), and the `Dockerfile` translates its `make_template()`
(non-docker variant) step by step. Everything upstream leaves floating is
pinned where it can be:

| Component | Upstream | This image |
| --- | --- | --- |
| Base image | `python:3.13` | `python:3.13@sha256:138ea058…4d920d` (Python 3.13.16, Debian 13) |
| Node.js | `setup_20.x` script, newest 20.x | nodesource `nodejs=20.20.2-1nodesource1`, repository key SHA-256 `b42e0321…0a271d` |
| `e2b_charts` | unpinned | `1.0.0` (the repository's own `chart_data_extractor` at the commit) |
| Python packages | `requirements.txt` | as upstream (top-level pins; dependencies resolve at build time) |
| R | `r-base=4.5.*` | same (Debian 13 has 4.5.0-3) |
| IRkernel | cloud.r-project.org, newest | Posit Package Manager CRAN snapshot `2026-10-01` (IRkernel 1.3.2) |
| ijavascript | `e2b-dev/ijavascript` default branch | commit `79cb7d56dcfe0df9ff55eff0ca4dc920a6dcc361` (5.2.1); its git and semver dependencies still float |
| bash_kernel | unpinned | `0.10.0` |
| JDK | OpenJDK 11 GA tarball | same, SHA-256 `3784cfc4…6610f2e` as published by java.net |
| IJava | 1.3.0 release zip | same, observed SHA-256 `484cc625…ec246b2` (no published checksum) |
| Server venv | `server/requirements.txt` | as upstream (all pinned there) |

Debian packages come from the live Debian and nodesource mirrors, so a
rebuild picks up their security updates; the image's SHA-256 changes with
them. Unlike upstream, apt installs skip recommended packages, and man and
info pages, message catalogs, package documentation (copyright files stay)
and the JDK's `jmods` and `src.zip` are removed.

There is no systemd in the guest, so upstream's `jupyter.service` and
`code-interpreter.service` become one supervisor,
`/root/.jupyter/sandboxd-start.sh` (root, 0755). It runs in the foreground
until killed: Jupyter Server (`MATPLOTLIBRC` set, stdout discarded), then,
once `/root/.jupyter/jupyter-healthcheck.sh` passes, the code-interpreter
server (`uvicorn main:app` on `0.0.0.0:49999`). Either one is restarted 1 s
after it exits; when Jupyter exits, the code-interpreter server and the
kernels Jupyter started are stopped too and everything restarts. Its own
messages go to `/var/log/sandboxd-start.log`, Jupyter's stderr to
`/var/log/jupyter.log`, the server's output to
`/var/log/code-interpreter.log`. A second instance exits at once.

sandboxd starts it through the template's start and ready commands: after
envd's `/init` it runs the start command once as root through envd
(`/bin/bash -l -c <start-cmd>`), does not wait for it, then runs the ready
command until it exits 0 (at most `-template-ready-timeout`, default 3m, or the create fails). The
registration:

```sh
-register-template 'id=code-interpreter-v1,image=/var/lib/sandboxd-fc/images/code-interpreter-amd64-<sha>.ext4,profile=e2b,envd-version=0.9.0,port=49999,start-cmd=/root/.jupyter/sandboxd-start.sh,ready-cmd=curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:49999/health'
```

Measured on this host's Firecracker worker (2 vCPUs, `-memory-mib 2048`,
images `code-interpreter-amd64-487b6992d8d3` and `-a5e50c1be0ff` (the latter
with the guest agent that closes a port stream as soon as the guest port
closes), stock `e2b` and `e2b_code_interpreter` SDKs):

- Create to ready (boot, envd init, start, ready): 5.1–6.9 s.
- All five kernels execute through `/execute`, including create-time
  `envs` in python and bash; a matplotlib plot returns a PNG and chart data.
- Guest memory used (`free -m`): about 110 MiB booted, 390 MiB ready (the
  server opens python and javascript contexts), 730–760 MiB with all five
  kernels started. `-memory-mib 2048` is the recommended size; it leaves
  about 1.2 GiB for user code.
- `kill -9` of the code-interpreter server: healthy and executing again
  within 4 s, measured inside the guest; of Jupyter Server: within 6 s (new
  kernels; the old ones are gone, as under systemd). Through sandboxd's port
  proxy, `run_code` works again 3.0 s after the server is killed and 5.1 s
  after Jupyter is (image `-a5e50c1be0ff`; before it, a stale pooled stream
  made the first call hang for 20 s).
- Stock upstream suites against this worker (image `-a5e50c1be0ff`):
  code-interpreter Python 163 passed, 0 failed; JS 82 passed, 0 failed.

Upstream's tests kill with `kill -9 $(pgrep -f 'jupyter server')` and
`kill -9 $(pgrep -f 'uvicorn main:app')`. The supervisor's own command lines
contain neither string. Jupyter's process is
`/usr/local/bin/python3.13 /usr/local/bin/jupyter-server …`, so the first
command matches only the shell running it, here as on E2B.

Licensing: the template is Apache-2.0; the image carries upstream's license
and a source note in `/usr/share/doc/code-interpreter/` (`LICENSE`,
`SOURCE`), next to envd's in `/usr/share/doc/envd/`. The kernels and
packages keep their own licenses (Debian's copyright files are in
`/usr/share/doc/<package>/copyright`).

## Running

```sh
sandboxd -driver firecracker -max-vms 2 \
  -image /var/lib/sandboxd-fc/images/review-amd64-<sha>.ext4 \
  -fc-kernel /var/lib/sandboxd-fc/kernel/vmlinux-6.1.186 \
  -template review-amd64 -cpus 2 -memory-mib 2048 \
  -db … -api-key-file … -domain … -gateway-host … -worker-id …
```

The daemon must run as root (jailer, namespaces, nftables). `-max-vms`
defaults to 2 for this driver, with at most 64 slots. `-slot`, `-pin-image`,
`-pf-socket` and the model relay flags are Apple-only, and the Firecracker
driver rejects them. The other `-fc-*` flags are listed in `sandboxd -h`.

For the stock E2B SDKs, also register an `e2b` template on the E2B base
image and give the daemon the token secret those templates need (a 0600
file of at least 32 bytes); `alias=base` makes it the SDKs' default
template:

```sh
  -token-secret-file /var/lib/sandboxd/token-secret \
  -register-template id=e2b-base,alias=base,profile=e2b,envd-version=0.9.0,image=/var/lib/sandboxd-fc/images/e2b-amd64-<sha>.ext4
```

Clients then set `E2B_API_URL` and `E2B_SANDBOX_URL` to sandboxd's URL,
`E2B_API_KEY` to the API key and `E2B_DOMAIN` to `-domain`; the README's
[Linux quick start](../README.md#quick-start-linux-firecracker) has the
full sequence.

It needs no terminal and works under any umask, so it can run as a
systemd or other service with `UMask=0077` and stdin on `/dev/null`. The
driver sets every jail mode explicitly; the VMM's UID must be able to read
the root-owned `/vm.json`, kernel and root image in its jail.

A failed create answers `503` with a fixed message and is logged with its
cause by the worker and by the gateway. Once the jailer has run, the cause
also carries the quoted first 64 lines (at most 16 KiB) of the jailer's and
the VMM's stdout and stderr, where Firecracker writes a startup panic; with
`-fc-console-log` they are read from the jail's `console.log` before the
failed VM's jail is removed. That output is the guest serial console, so it
is guest-controlled: it appears only in the log, never in an API response.

To run it as a worker that another sandboxd gateway enrolls (see
[Multiple workers](compatibility.md#multiple-workers)), replace the gateway
flags with `-worker-key-file <0600 file>` and keep `-worker-id`. It then
declares architecture `amd64` and driver `firecracker`. The gateway enrolls
it with `-enroll id=<worker-id>,url=<https URL>,key-file=<same key>` and
`-template-arch review-amd64=amd64`. The worker destroys each VM at the end
time the gateway sent, capped by its own `-max-ttl` (default 1h), even when
it cannot reach the gateway.

### Standalone gateway on the client's host

[`examples/sandboxd-firecracker.service`](examples/sandboxd-firecracker.service)
is a sample systemd unit for a Firecracker gateway that serves a client on
the same host (for example Gitmoot, as its `sandboxd-linux` provider): root,
`UMask=0077`, stdin on `/dev/null`, API on `127.0.0.1:43190`, at most two
VMs of 2 vCPUs and 2 GiB, template `review-amd64` served from the Go review
image, `-fc-host-port 8443` for the host's credential gateway, and the
ledger (`ledger.sqlite`) and API key (`api-key`, 0600) in
`/var/lib/sandboxd-linux` (0700). The client uses
`http://127.0.0.1:43190` as both API and envd base URL; envd requests
carry `Host: 127.0.0.1:43190`, which `-gateway-host 127.0.0.1` matches.

## Tests

- `go test ./internal/vm ./internal/guestagent ./cmd/sandboxd`: driver
  logic against a fake host, with no KVM needed. It covers jail layout,
  jailer limits, the disk floor, cleanup after failed creates, restart
  reconciliation, firewall loss, the rulesets (golden files in
  `internal/vm/testdata`, with and without `-fc-host-port`, and readbacks
  captured from nft 1.0.9), the symlink-safe vsock dial (a replaced socket
  or run directory never reaches another listener) and the guest agent
  protocol.
- `sudo SANDBOXD_FC_KVM=1 go test ./internal/vm -run TestFirecrackerKVM`:
  boots real VMs from the install above. `TestFirecrackerKVM` checks exec,
  exit codes, CopyIn, cross-guest isolation, host and private probes against
  a host listener on every interface, internet access and cleanup;
  `TestFirecrackerKVMHostPort` the `-fc-host-port` exception;
  `TestFirecrackerKVMGoImage` the Go review image.
