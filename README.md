# sandboxd

A self-hosted, E2B-compatible sandbox server where every sandbox is a real
VM, on Linux (Firecracker/KVM) or Apple-silicon Macs.

[![CI](https://github.com/gitmoot/sandboxd/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gitmoot/sandboxd/actions/workflows/ci.yml)
[![Conformance](https://github.com/gitmoot/sandboxd/actions/workflows/conformance.yml/badge.svg?branch=main)](docs/conformance-matrix.md)
[![Release](https://img.shields.io/github/v/release/gitmoot/sandboxd)](https://github.com/gitmoot/sandboxd/releases/latest)
[![License](https://img.shields.io/github/license/gitmoot/sandboxd)](LICENSE)

sandboxd serves E2B's HTTP API on loopback and backs each sandbox with its
own Linux VM: a Firecracker microVM on a Linux/KVM host, or an Apple
[`container`](https://github.com/apple/container) VM on a Mac. A SQLite
ledger tracks every VM it creates. Point the stock E2B SDKs at it with
`E2B_API_URL`, `E2B_SANDBOX_URL`, `E2B_API_KEY` and `E2B_DOMAIN`; no code
change is needed for the supported operations.

> [!IMPORTANT]
> Read the limits first:
> - The stock E2B SDKs work only against the **Linux** worker. The Mac worker
>   serves only the API subset that Gitmoot's pinned client uses
>   ([#38](https://github.com/gitmoot/sandboxd/issues/38)).
> - There is **one API key per server** and no tenants or quotas. A server
>   is meant for one operator or team, not for strangers sharing it.
> - Pause, resume, snapshots, fork, volumes, secrets and template builds
>   through the API are refused (see [Not supported yet](#not-supported-yet)).

sandboxd runs Gitmoot's opt-in Mac execution provider and its Linux
provider on a Firecracker host.

## What works

| | Linux (Firecracker/KVM, x86_64) | Mac (Apple `container`, Apple silicon) |
| --- | :---: | :---: |
| Guest architecture | linux/amd64 | linux/arm64 |
| Stock E2B SDKs (Python and JS `e2b` 2.52.0): create, connect, list, kill, timeouts, metrics, logs | ✅ | ❌ ([#38](https://github.com/gitmoot/sandboxd/issues/38)) |
| `commands` (run, stdin, kill, list, connect), `pty`, `files` (read, write, list, watch, signed URLs) | ✅ | ❌ |
| Code interpreter (`run_code`), `code-interpreter-v1` template | ✅ | ❌ |
| Guest ports through the gateway, with routing headers and a traffic token | ✅ | ❌ |
| `envVars`, `user="root"` inside the VM | ✅ | ❌ |
| Gitmoot's pinned client (create, upload, start, delete) | ✅ | ✅ |
| Internet egress; private ranges and the host blocked | ✅ | ✅ |
| One gateway scheduling onto several enrolled workers | ✅ | ✅ |

The Linux column comes from two sources:

- **CI, every pull request.** [`docs/conformance-matrix.md`](docs/conformance-matrix.md)
  records the outcome of every upstream SDK test, run unchanged against
  `sandboxd-dev` (the real control and data plane on a no-isolation process
  driver); CI fails when any outcome changes. Tests that need sandboxd:

  | Suite | Pass | Fail |
  | --- | ---: | ---: |
  | Python `e2b` 2.52.0 | 249 | 113 |
  | JS `e2b` 2.52.0 | 134 | 214 |
  | Python code-interpreter 2.10.1 | 0 | 131 |
  | JS code-interpreter 2.8.0 | 0 | 69 |
  | Gitmoot pinned client | 1 | 0 |

  Of the `e2b` failures, 109 (Python) and 201 (JS) are features sandboxd
  refuses on purpose: pause and resume (including auto-pause),
  snapshots, fork, MCP gateways, network policy, IAM, volumes, secrets,
  template builds. The other 4 and 13
  are `get_host` (needs wildcard DNS) and client request-plumbing tests. The
  matrix lists every failing test. The code-interpreter suites fail in CI
  because the dev driver has no code-interpreter server.
- **A real Firecracker worker.** With the `code-interpreter-v1` image, the
  stock code-interpreter suites passed in full on 2026-10-05: Python 163
  passed, 0 failed; JS 82 passed, 0 failed
  ([details](docs/firecracker.md#code-interpreter-image)). This run is
  repeated by hand, not in CI, because GitHub runners have no KVM.

[`docs/compatibility.md`](docs/compatibility.md) describes the API surface
route by route.

## Not supported yet

- **Tenants and quotas.** One API key per server
  ([#27](https://github.com/gitmoot/sandboxd/issues/27), M4).
- **Stock SDKs on the Mac.** The upstream envd data plane is not on the
  Apple worker yet ([#38](https://github.com/gitmoot/sandboxd/issues/38)).
- **`get_host` and per-sandbox hostnames.** `<port>-<id>.<domain>` needs
  wildcard DNS and TLS, so it is off by default (`-port-hosts` turns it on).
  Guest ports work through the gateway host with the SDKs' routing headers.
- **Pause, resume, snapshots and fork** (M5). Refused with a `501` and a
  clear message.
- **Template builds through the API.** Templates are built with the scripts
  in [`images/`](images) and registered by the operator with
  `-register-template`.
- **Volumes, secrets, IAM, MCP gateways, network policy updates and public
  guest ports.** Refused with a `501`
  ([full list](docs/compatibility.md#not-supported)).
- **Firecracker on arm64 hosts.** The Firecracker worker runs only on
  x86_64. The linux-arm64 release has only `sandboxd`, for a gateway that
  schedules onto enrolled workers.

## Security model

- **A VM per sandbox.** Each sandbox is its own Linux VM with its own disk
  and network; there are no host mounts. On Linux it is a Firecracker
  microVM started by the jailer, with its own unprivileged UID, cgroup and
  network namespace. On the Mac it is an Apple `container` VM on its own
  host-only network.
- **Internet yes, private networks no.** Guests reach the public internet
  over IPv4. Private and special ranges (RFC 1918, CGNAT and Tailscale
  `100.64/10`, link-local including 169.254.169.254, loopback, multicast), every
  address of the host itself (except one port the operator may open for a
  local service) and other guests are blocked; guest IPv6 is blocked too.
  Linux enforces this with nftables and a per-VM user-mode NAT, the Mac
  with a root PF helper. sandboxd runs no guest work until the rules are in
  place, and stops if a later check fails.
- **Root inside an `e2b` guest owns only that VM.** The SDK's
  `user="root"` is allowed; the boundary is the VM.
- **One API key, one operator.** `X-API-Key` gives full control of every
  sandbox on the server. Each sandbox also has its own envd access token,
  and guest ports need its traffic token. There are no accounts, so do not
  share a server between parties who do not trust each other.
- **Loopback only.** sandboxd listens on loopback. Put private HTTPS in
  front of it (Tailscale Serve, an SSH tunnel) if clients are on other
  machines; never expose it on a public address.

Details: [Linux isolation and egress](docs/firecracker.md),
[Mac PF helper and egress](docs/compatibility.md#guest-egress).

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/architecture-dark.svg">
    <img alt="sandboxd architecture: a client reaches the control API and guest data plane over private HTTPS; sandboxd records sandboxes in a SQLite ledger and drives Apple container VMs, one per sandbox on its own host-only network; a root PF helper firewalls the VMs; an optional model relay forwards guest model traffic to an operator upstream." src="docs/images/architecture-light.svg" width="560">
  </picture>
</p>

<sub>Diagram source: <a href="docs/images/architecture.mmd"><code>docs/images/architecture.mmd</code></a>.</sub>

The diagram shows the Mac worker. The Linux worker has the same control
plane, ledger and API; in place of Apple `container`, the PF helper and the
model relay, it runs a jailed Firecracker microVM per sandbox, reached over
vsock, behind an nftables table and a per-VM NAT
([docs/firecracker.md](docs/firecracker.md)).

- **Control plane**: create, connect, get, list, extend and kill sandboxes,
  metrics and logs. Each request needs `X-API-Key`. The ledger reserves
  capacity before a VM exists, and reconciliation removes VMs it does not
  know about.
- **Guest data plane**: commands, files and PTYs, authenticated by the
  sandbox's envd access token. On Linux, `e2b` templates run upstream
  [E2B envd](https://github.com/e2b-dev/infra) in the guest, reached only
  over vsock.
- **Gateway and workers**: one sandboxd can enroll other sandboxd workers
  (Apple or Firecracker) and schedule by architecture and free capacity
  ([Multiple workers](docs/compatibility.md#multiple-workers)).

## Quick start: Linux (Firecracker)

Needs an x86_64 Linux host with `/dev/kvm`, cgroup v2 (`cpu memory pids`
enabled at the root), `nft`, `ip`, `nsenter`, `unshare`, `setpriv`,
`slirp4netns` (tested with 1.2.1), `curl` and Docker (to build the guest
images), and about 20 GB free: each VM gets a 10 GiB home disk, and 8 GiB
must stay free beyond it. The daemon runs as root. Releases after v0.2.0
include Linux tarballs.

**1. Get sandboxd and the build scripts.** In a root shell (`sudo -s`),
check out the release tag and download its tarball. Compare the archive's
SHA-256 with the one on the
[release page](https://github.com/gitmoot/sandboxd/releases/latest) before
installing:

```sh
tag=<tag>
git clone --branch "$tag" https://github.com/gitmoot/sandboxd && cd sandboxd
d=$(mktemp -d)
(cd "$d" && curl -fsSLO "https://github.com/gitmoot/sandboxd/releases/download/$tag/sandboxd-$tag-linux-amd64.tar.gz" \
  && curl -fsSLO "https://github.com/gitmoot/sandboxd/releases/download/$tag/SHA256SUMS" \
  && sha256sum -c --ignore-missing SHA256SUMS && tar -xzf "sandboxd-$tag-linux-amd64.tar.gz")
install -m 0755 "$d/sandboxd" /usr/local/bin/sandboxd
```

To build from source instead, see [docs/firecracker.md](docs/firecracker.md#install).

**2. Install the pinned Firecracker v1.17.0, jailer and guest kernel
6.1.186** (each download is checked against a SHA-256 in the script):

```sh
images/linux-amd64-fc/install-firecracker.sh /var/lib/sandboxd-fc
```

**3. Build the guest images.** Each script prints the image path. The
review image serves the primary template every sandboxd needs; the `e2b`
image runs upstream envd 0.9.0 and serves the stock SDKs.

```sh
SANDBOXD_GUEST_AGENT="$d/sandboxd-guest-agent" images/linux-amd64-fc/build.sh /var/lib/sandboxd-fc
SANDBOXD_GUEST_AGENT="$d/sandboxd-guest-agent" images/e2b-amd64-fc/build.sh /var/lib/sandboxd-fc
```

**4. Create the secrets and run sandboxd.** Replace the two `<sha>` with the
printed names.

```sh
install -d -m 0700 /var/lib/sandboxd
(umask 077; head -c 32 /dev/urandom | base64 > /var/lib/sandboxd/api-key
  head -c 48 /dev/urandom | base64 > /var/lib/sandboxd/token-secret)

sandboxd -driver firecracker \
  -listen 127.0.0.1:43190 \
  -db /var/lib/sandboxd/ledger.sqlite \
  -api-key-file /var/lib/sandboxd/api-key \
  -token-secret-file /var/lib/sandboxd/token-secret \
  -domain sandboxd.internal -gateway-host 127.0.0.1 \
  -worker-id linux-1 \
  -fc-kernel /var/lib/sandboxd-fc/kernel/vmlinux-6.1.186 \
  -template review-amd64 \
  -image /var/lib/sandboxd-fc/images/review-amd64-<sha>.ext4 \
  -register-template id=e2b-base,alias=base,profile=e2b,envd-version=0.9.0,image=/var/lib/sandboxd-fc/images/e2b-amd64-<sha>.ext4
```

`alias=base` makes the template the SDKs' default. Defaults: at most 2 VMs
(`-max-vms`, up to 64), 2 vCPUs (`-cpus`), 4096 MiB (`-memory-mib`), a 1 h
maximum lifetime (`-max-ttl`). A sample systemd unit is in
[`docs/examples`](docs/examples/sandboxd-firecracker.service).

**5. Use the stock Python SDK.** In another shell on the same host:

```sh
python3 -m venv venv && venv/bin/pip install e2b==2.52.0
export E2B_API_URL=http://127.0.0.1:43190
export E2B_SANDBOX_URL=http://127.0.0.1:43190
export E2B_API_KEY=$(sudo cat /var/lib/sandboxd/api-key)
export E2B_DOMAIN=sandboxd.internal
venv/bin/python quickstart.py
```

`quickstart.py`:

```python
from e2b import Sandbox

sbx = Sandbox.create()  # "base" is the e2b template's alias
print("sandbox", sbx.sandbox_id)
result = sbx.commands.run("uname -sm; whoami")
print(result.stdout, end="")
sbx.files.write("/home/user/hello.txt", "hello from sandboxd\n")
print(sbx.files.read("/home/user/hello.txt"), end="")
sbx.kill()
print("killed", not sbx.is_running())
```

Expected output:

```text
sandbox sandboxd-<id>
Linux x86_64
user
hello from sandboxd
killed True
```

For clients on other machines, put private HTTPS in front of the loopback
listener and use that URL for `E2B_API_URL` and `E2B_SANDBOX_URL`; set
`-gateway-host` to its host name. The code-interpreter template, enrolled
workers and every `-fc-*` flag are in [docs/firecracker.md](docs/firecracker.md).

## Quick start: Mac (Apple `container`, Gitmoot client only)

The Mac worker serves Gitmoot's pinned client, not the stock SDKs
([#38](https://github.com/gitmoot/sandboxd/issues/38)). It needs:

- An Apple-silicon Mac, on a macOS version that Apple `container` supports.
- Apple's [`container`](https://github.com/apple/container) CLI, tested with
  **1.4.1**, installed root-owned at `/usr/local/bin/container` (or pass
  `--container-cli`), with its Linux kernel installed. sandboxd starts
  Apple's services after a reboot but never installs the kernel.
- A dedicated unprivileged worker account that owns the Apple container
  service, and the stock `root ALL=(ALL) ALL` sudoers rule (the helper runs
  `container` as that account).
- Private HTTPS in front of sandboxd's loopback listener (Tailscale Serve or
  an SSH tunnel).

Commands run on the Mac unless noted. Updates, logs and uninstall are in
[Operating the PF helper](docs/compatibility.md#operating-the-pf-helper).

**1. Start Apple's runtime and build the guest image** (as the worker
account, from a checkout of this repository):

```sh
container system start --enable-kernel-install
container build --platform linux/arm64 --tag sandboxd/review-go126:<version> images/linux-arm64
```

**2. Create one host-only network per concurrent VM** (a *slot*), with
distinct IPv4 subnets. Let Apple choose the IPv6 prefix.

```sh
container network create --internal --subnet 192.168.130.0/24 \
  --label gitmoot.sandboxd.network=apple-v1 sandboxd-slot-1
container network create --internal --subnet 192.168.131.0/24 \
  --label gitmoot.sandboxd.network=apple-v1 sandboxd-slot-2
```

**3. Install the PF helper and sandboxd from a release.** Open the
[release page](https://github.com/gitmoot/sandboxd/releases/latest) in your
own browser, copy the archive's SHA-256, then run this from the worker
account:

```sh
sudo sh -c 'set -e; d=$(mktemp -d /var/root/sandboxd.XXXXXX); cd "$d"; curl -fsSLO https://github.com/gitmoot/sandboxd/releases/download/<tag>/sandboxd-<tag>-darwin-arm64.tar.gz; echo "<sha256>  sandboxd-<tag>-darwin-arm64.tar.gz" | shasum -a 256 -c; tar -xzf sandboxd-<tag>-darwin-arm64.tar.gz; ./sandboxd-pf-helper install; cd /; rm -rf "$d"'
```

`install` registers the `org.gitmoot.sandboxd-pf-helper` launchd service,
installs `sandboxd` at `/usr/local/libexec/sandboxd`, and prints the
`--slot` flags that sandboxd needs. Later updates are a single command,
which verifies the release before installing it:

```sh
sudo sandboxd-helper-update
```

**4. Run sandboxd** as the worker account. The API key file must be mode
0600 and hold one value of at least 8 bytes. Keep it and the ledger outside
disposable paths.

```sh
/usr/local/libexec/sandboxd \
  --listen 127.0.0.1:43180 \
  --db <state-dir>/sandboxd.db \
  --api-key-file <state-dir>/api-key \
  --image sandboxd/review-go126:<version> \
  --template review-arm64 \
  --pin-image docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc \
  --pf-socket /private/var/run/sandboxd-pf/helper.sock \
  --worker-id mac-local \
  --domain <private-domain> \
  --gateway-host <mac-host> \
  --slot name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=<ula-prefix>/64 \
  --slot name=sandboxd-slot-2,ipv4=192.168.131.0/24,gw=192.168.131.1,ipv6=<ula-prefix>/64
```

Copy the `--slot` lines exactly as `install` printed them, in the same order.
`--pin-image` and `--worker-id` must match the helper's; the values above are
the helper's defaults. Optional flags: `--cpus` (default 2),
`--memory-mib` (default 4096), `--max-vms` (default one per slot) and
`--max-ttl` (default `1h`).

**5. Expose it privately.** sandboxd listens only on loopback:

```sh
# On the Mac: HTTPS on your tailnet
tailscale serve --bg --https=8443 http://127.0.0.1:43180

# Or, for testing, from your client: a loopback tunnel
ssh -N -L 43180:127.0.0.1:43180 <user>@<mac-host>
```

**6. Create and delete a sandbox.**

```sh
KEY=$(cat <state-dir>/api-key)

curl -sS -X POST http://127.0.0.1:43180/sandboxes \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"templateID":"review-arm64","timeout":300,"secure":true,
       "metadata":{"job_id":"readme-demo","attempt":"1","lifecycle_generation":"0"}}'
# 201 {"sandboxID":"sandboxd-…","envdAccessToken":"…",...}

curl -sS -o /dev/null -w '%{http_code}\n' -X DELETE \
  -H "X-API-Key: $KEY" http://127.0.0.1:43180/sandboxes/<sandboxID>
# 204
```

`timeout` is in seconds. Each create needs a new `job_id`, or a higher
`attempt` for the same one; otherwise sandboxd answers 409.

## Using with Gitmoot

Declare the Mac beside Gitmoot's default cloud E2B provider in
`config.toml`:

```toml
[remote_exec.mac]
api_key_file = "/path/to/sandboxd-api-key"
template = "review-arm64"
omp_template = "review-arm64"
base_url = "https://<mac-host>:8443"
envd_base_url = "https://<mac-host>:8443"
omp_linux_arm64_file = "/path/to/omp-linux-arm64"
credential_gateway_url = "https://<first-slot-gateway>:43181"
max_concurrent = 1
```

`max_concurrent` is the Mac's capacity. `credential_gateway_url` also
requires `credential_gateway_listen` and `credential_gateway_url` in
`[remote_exec]`. A job uses the Mac only when you ask for it:

```sh
gitmoot review request --pr <number> --repo <owner>/<repo> --exec-provider mac
```

A Linux Firecracker gateway serves Gitmoot the same way with
`template = "review-amd64"`; see
[Standalone gateway on the client's host](docs/firecracker.md#standalone-gateway-on-the-clients-host).
Gitmoot's
[remote execution docs](https://github.com/gitmoot/gitmoot/blob/main/docs/remote-exec.md)
have the full provider setup.

## Roadmap

- Tenants, quotas and egress policy
  ([#27](https://github.com/gitmoot/sandboxd/issues/27)).
- The upstream envd data plane on the Mac, so the stock SDKs work there
  ([#38](https://github.com/gitmoot/sandboxd/issues/38)).
- Running a Mac and a Linux worker together in production
  ([#11](https://github.com/gitmoot/sandboxd/issues/11)).
- Recovery after a reboot with no manual step
  ([#7](https://github.com/gitmoot/sandboxd/issues/7)).
- Tracking for general E2B SDK compatibility:
  [#21](https://github.com/gitmoot/sandboxd/issues/21).

## Docs

- [`docs/firecracker.md`](docs/firecracker.md): the Linux/KVM worker: install,
  isolation and egress, images (review, `e2b`, code-interpreter), running it.
- [`docs/compatibility.md`](docs/compatibility.md): the API surface, template
  profiles, what is refused, multiple workers, the Mac's network slots and
  PF helper.
- [`docs/conformance-matrix.md`](docs/conformance-matrix.md): per-test SDK
  outcomes, regenerated by `conformance/run.py`.
- [`images/`](images): the guest image builds.

## License

[Apache License 2.0](LICENSE). Third-party components and their licenses
are listed in [NOTICE](NOTICE).
