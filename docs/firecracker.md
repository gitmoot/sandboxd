# Linux worker: Firecracker driver

`sandboxd -driver firecracker` runs each sandbox as a Firecracker microVM on
Linux/KVM (x86_64). It serves the same API and guest contract as the Apple
worker, for the same Gitmoot review profile. Tracking: [#29](https://github.com/gitmoot/sandboxd/issues/29).

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
  --disable-dns`. The namespace table `inet sbx_vm` forwards only from
  `sbxvm0` to `sbxsl0`, and only to addresses outside the deny list. It
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
re-checks it (`nft -s list table inet sbx_fc`) before every create and every
second during exec, and destroys the guest if it changed. On a clean
shutdown the daemon destroys every guest, then removes the table and the
cgroup parent.

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

## Install and rebuild (`/var/lib/sandboxd-fc`)

Host prerequisites: `/dev/kvm`, cgroup v2 with `cpu memory pids` enabled at
the root, `nft`, `ip`, `nsenter`, `unshare`, `setpriv` and `slirp4netns`
(tested with 1.2.1), plus Docker for building the image.

```sh
# Firecracker v1.17.0 + jailer and guest kernel 6.1.186, each SHA-256 pinned.
sudo images/linux-amd64-fc/install-firecracker.sh /var/lib/sandboxd-fc
# Read-only review root image (debian:bookworm-slim by digest, git, bash, curl,
# gcc/g++/make, python3, user 1000, plus the guest agent). Prints the path,
# images/review-amd64-<sha256 prefix>.ext4, about 600 MB.
sudo images/linux-amd64-fc/build.sh /var/lib/sandboxd-fc
```

| Path | Content |
| --- | --- |
| `bin/firecracker`, `bin/jailer` | v1.17.0 x86_64, release tarball SHA-256 `06094a11…de558` |
| `kernel/vmlinux-6.1.186` | Firecracker CI kernel, SHA-256 `ea0e55d0…f69c8` |
| `images/review-amd64-<sha>.ext4` | The read-only root image, with its `.sha256` |
| `jail/`, `run/` | Per-VM state, empty when no VM exists |

Go and the review module cache, which `images/linux-arm64` includes, are
not in this image yet.

## E2B base image

Templates with `profile=e2b` use this image instead of the review image.
Build it like the review image (root, from the repository root):

```sh
# Prints the path, images/e2b-amd64-<sha256 prefix>.ext4, about 340 MB.
sudo images/e2b-amd64-fc/build.sh /var/lib/sandboxd-fc
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

It needs no terminal and works under any umask, so it can run as a
systemd or other service with `UMask=0077` and stdin on `/dev/null`. The
driver sets every jail mode explicitly; the VMM's UID must be able to read
the root-owned `/vm.json`, kernel and root image in its jail.

To run it as a worker that another sandboxd gateway enrolls (see
[Multiple workers](compatibility.md#multiple-workers)), replace the gateway
flags with `-worker-key-file <0600 file>` and keep `-worker-id`. It then
declares architecture `amd64` and driver `firecracker`. The gateway enrolls
it with `-enroll id=<worker-id>,url=<https URL>,key-file=<same key>` and
`-template-arch review-amd64=amd64`. The worker destroys each VM at the end
time the gateway sent, capped by its own `-max-ttl` (default 1h), even when
it cannot reach the gateway.

## Tests

- `go test ./internal/vm ./internal/guestagent ./cmd/sandboxd`: driver
  logic against a fake host, with no KVM needed. It covers jail layout,
  jailer limits, the disk floor, cleanup after failed creates, restart
  reconciliation, firewall loss, the rulesets, the symlink-safe vsock dial
  (a replaced socket or run directory never reaches another listener) and
  the guest agent protocol.
- `sudo SANDBOXD_FC_KVM=1 go test ./internal/vm -run TestFirecrackerKVM`:
  boots two real VMs from the install above. It checks exec, exit codes,
  CopyIn, cross-guest isolation, host and private probes against a host
  listener on every interface, internet access and cleanup.
