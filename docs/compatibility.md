# Gitmoot E2B subset

Client revision: `gitmoot/gitmoot@10f31189f6f23119f03aab697bce00d4d59e3291`, package `internal/execbackend/e2b`. This is a **subset**, not an E2B SDK implementation. The client fixture tests at that revision are the reference for malformed responses, redirects, truncated streams, and ambiguous failures. The opt-in `TestSandboxdPinnedClientConformance` in that same package exercises the actual client against sandboxd and a real VM; it passed on Apple container 1.4.1 over a private SSH tunnel on 2026-09-24. The Mac service used a temporary key and was stopped afterward; production routing was not changed.

| Plane | Supported operation | Authentication and result |
| --- | --- | --- |
| Control | `POST /sandboxes` | `X-API-Key`; known template, secure mode, bounded TTL and owner metadata; `201` with `sandboxID`, `envdAccessToken` and VM shape. Unknown template and unsupported options are rejected. |
| Control | `GET /sandboxes/{id}` | `X-API-Key`; `200` for live VM; per-ID `404` remains **inconclusive** to the pinned Gitmoot client; unavailable observation is `503`. |
| Control | `GET /v2/sandboxes?limit=100&nextToken=...` | `X-API-Key`; sorted stable-ID pages, `X-Next-Token` and `X-Total-Running`; inventory failure is `503`, never an empty success. The complete inventory, not a per-ID 404, proves absence. |
| Control | `POST /sandboxes/{id}/timeout`, `DELETE /sandboxes/{id}` | `X-API-Key`; bounded extension, idempotent confirmed destroy; success `204`; uncertain cleanup is `503` and retains capacity. |
| Control | `GET /sandboxes/{id}/metrics` | `X-API-Key`; measured CPU and memory values from Apple VM stats; `200` array or `503` on incomplete samples. No invented disk usage or cloud charge. |
| Guest | `POST /files?username=user&path=/home/user/...` | `X-Access-Token` per-VM capability and sandbox ID/port routing headers; bounded regular file, confined path, no host mounts. |
| Guest | `POST /process.Process/Start` | Same capability; Connect JSON framed start/data/end messages, flushed stdout/stderr, exit status; combined stdout/stderr capped at 64 MiB per process stream, with VM teardown on overflow; no stdin or unsupported process RPCs. |

The guest endpoint accepts either the private wildcard host `49983-<id>.<domain>` or an explicitly configured single gateway host with `E2b-Sandbox-Id` and `E2b-Sandbox-Port: 49983`. The latter requires Gitmoot's explicit `e2b_envd_base_url` and `provider = "mac"` configuration. The control endpoint is separate from the guest address. Both require private HTTPS in deployment; loopback HTTP was used only for local conformance through an SSH tunnel.

A canceled or transport-failed guest execution revokes its capability and
destroys the **entire VM**, because Apple `container exec` alone leaves the
guest process alive when the host CLI disconnects. An uncertain destroy remains
reserved as `unknown` for reconciliation. Set
`SANDBOXD_CONFORMANCE_CANCEL=1` to check cancellation against a real VM;
the Mac run removed both its VM and its private volume.

Before reserving capacity, reconciliation destroys driver-owned VMs that
have no live ledger row; a failed inventory or destroy blocks admission.
If the ledger itself is lost, separately inspect labeled private volumes
without a VM: VM inventory alone cannot prove those volumes were removed.

VMs and volumes carry a `gitmoot.sandboxd.worker` ownership label. Assign
a unique, stable `--worker-id` of at most 63 lowercase letters, digits, and
hyphens (starting with a letter), and keep it with the same durable ledger
across restarts. Stop the old daemon before restarting that identity; never
use one worker ID with a different ledger. The worker ignores another
worker's labeled VMs.

Before upgrading from an owner-only-label build, drain its VMs and verify
its volumes are gone; they cannot be claimed by the worker-scoped driver.

Run conformance against an already running, private sandboxd instance with a real guest image:

```sh
SANDBOXD_CONFORMANCE_URL=https://<private-gateway> \
SANDBOXD_CONFORMANCE_KEY_FILE=<0600-control-key-file> \
SANDBOXD_CONFORMANCE_TEMPLATE=<allowlisted-template> \
go test ./internal/execbackend/e2b -run TestSandboxdPinnedClientConformance -count=1 -v
```

Run that command from the pinned Gitmoot checkout. Without these variables the opt-in real-VM test skips; the ordinary Gitmoot client fixture tests still run offline. The canary creates and deletes one VM; independently inspect Apple container and volume inventories afterward. It must not be used as permission to redirect production jobs.

Set `SANDBOXD_CONFORMANCE_OMP_FILE` to a verified Linux ARM64 OMP executable
to also upload it and run `omp --version` inside the VM. On the Mac Studio,
the pinned v17.3.5 asset executed successfully; that checks architecture and
upload, not model access or a full PR review.

Security gate: Apple `hostOnly` is **not** a host firewall. A guest reached Mac
wildcard listeners over IPv4, IPv6 ULA, and IPv6 link-local. Mac IPv4 and IPv6
forwarding were enabled; a controlled literal-IP egress timeout did not prove
Internet isolation. One-port PF probes counted blocked guest packets on the
ephemeral Mac bridge (`bridge102`), but the broad deny-all canary expired without
a valid counter read. No production PF policy or private HTTPS endpoint was
deployed. Do not run untrusted PR code or production routing on that evidence.

The selected root-owned PF helper (`cmd/sandboxd-pf-helper`) has passed a
bounded deny-only Mac canary, but is **not approved for production traffic**.
`sandboxd-pf-helper install` makes it a launchd system service (see
[Operating the PF helper](#operating-the-pf-helper)). Its root-owned launchd
configuration must fix the dedicated worker UID/GID and HOME, worker ID,
root-owned `container` CLI, every network slot (below), trusted pin image at
an OCI digest, SHA-256 of reviewed `pfctl -sr` output, and a socket under a
root-owned non-writable directory. For every slot it checks the network
label/mode/addresses, a read-only capability-dropped pin VM on that network,
and exactly one live bridge carrying that slot's gateway, ULA and link-local
addresses (a bridge matching two slots, or two bridges matching one slot, is
refused); then PF enabled and not skipping any slot bridge, unchanged main
rules, and the exact configured anchor covering every slot bridge in slot
order. A slot network used by two VMs other than its pin, or a VM joining a
slot network to any other network, fails the check. Arm requires no VM other
than the pins on any slot network and clears old PF states only on the slot
bridges; it retries while any slot bridge is still configuring.
By default `--model-relay-port=0` retains the exact deny-only anchor. A
nonzero root-configured port adds, per slot, only a TCP pass from that slot's
IPv4 subnet to that slot's gateway address and that port; both IPv4/IPv6
block rules still follow. The helper refuses unrelated or changed anchor rules.
`sandboxd` requires the same pin digest through `--pin-image`, the same
`--slot` list, and the helper socket through `--pf-socket`; it stops
ordinary guests on gate failure and only requests anchor removal after every
VM has been deleted.

### Network slots: one host-only network per concurrent guest

Two guests on the same Apple host-only network can reach each other: PF on
the Mac never sees traffic inside one bridge, and macOS has no bridge
`private` flag. Guests on separate host-only networks could not reach each
other on the Mac Studio (TCP and ping blocked, with IP forwarding on). So
every concurrent guest gets its own network, a **slot**, and concurrency
equals the number of slots.

Create one network per slot with distinct, non-overlapping IPv4 subnets. Let
Apple choose each IPv6 ULA prefix: with `--subnet-v6`, `container` 1.4.1
reports the prefix as a host address (`fd…::1/64`), which never equals the
canonical `--slot` value, so the helper refuses that network.

```sh
container network create --internal --subnet 192.168.130.0/24 \
  --label gitmoot.sandboxd.network=apple-v1 sandboxd-slot-1
container network create --internal --subnet 192.168.131.0/24 \
  --label gitmoot.sandboxd.network=apple-v1 sandboxd-slot-2
container network create --internal --subnet 192.168.132.0/24 \
  --label gitmoot.sandboxd.network=apple-v1 sandboxd-slot-3
```

Copy each network's actual `status.ipv4Subnet`, `status.ipv4Gateway` and
`status.ipv6Subnet` from `container network inspect <name>` (mode must be
`hostOnly`) into one `--slot` per network, identical and in the same order
for both binaries:

```sh
sandboxd-pf-helper run ... \
  --slot name=sandboxd-slot-1,ipv4=192.168.130.0/24,gw=192.168.130.1,ipv6=fd1e:68b8:2ef4:5d01::/64 \
  --slot name=sandboxd-slot-2,ipv4=192.168.131.0/24,gw=192.168.131.1,ipv6=fd1e:68b8:2ef4:5d02::/64 \
  --slot name=sandboxd-slot-3,ipv4=192.168.132.0/24,gw=192.168.132.1,ipv6=fd1e:68b8:2ef4:5d03::/64
sandboxd ... (the same three --slot flags) [--max-vms N]
```

`sandboxd-pf-helper install` writes these `--slot` flags itself, one per
labelled host-only network in name order, and prints them for `sandboxd`.
Each `--slot` needs exactly the keys `name`, `ipv4` (canonical private /24 to
/30 containing `gw`), `gw` (private IPv4) and `ipv6` (canonical ULA /48 to
/64), in any order; unknown or repeated keys, a duplicate network, or
overlapping subnets are rejected; at most 16 slots. `--max-vms` defaults to
the slot count and may not exceed it. The service starts one pin VM per slot
(`sandboxd-pin-` plus a hash of the worker ID and network), records each
reservation's slot durably in the ledger (a unique index forbids two live rows
on one slot), and attaches each guest only to its slot network. A slot is
free again only once its row is `gone`; an `unknown` guest keeps its slot.
Reconciliation destroys a guest observed on a network other than its slot.

This replaces the single `--network`/`--gateway-ipv4`/`--network-ipv4`/
`--network-ipv6` helper flags and the service `--network` flag. To keep the
old `sandboxd-internal` network, pass it as one `--slot`. Stop the previous
build cleanly first so it removes its old pin VM (named from the worker ID
alone); a leftover VM on a slot network blocks arming. A ledger from a
pre-slot build keeps its rows; while any of them is not `gone`, admission is
refused (their guests' networks are unknown) until reconciliation proves
them gone.

The helper deliberately leaves the anchor in place on crash. The supervised
deny-only Mac canary blocked previously successful guest IPv4, IPv6 ULA, and
link-local connections while unrelated Mac/tailnet test traffic worked; the
trusted pin was removed and the owned anchor read back empty. Live rule
counters, helper failure while armed, reboot recovery, and any model pass
rule remain unverified. Do not admit untrusted work.

The optional fixed model relay transports TLS bytes without terminating TLS
or handling credentials. Gitmoot's mTLS broker listens on its own
`127.0.0.1:8443` and advertises its slot's gateway, e.g.
`https://192.168.130.1:8443`, so its server certificate must name every slot
gateway address a guest can see. A supervised SSH reverse
forward from that broker to the Mac binds only Mac `127.0.0.1:43184`:
`ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:43184:127.0.0.1:8443 jerry@<Mac-tailnet-IP>`.
The default PF anchor blocks the guest's model relay at its slot gateway
port 8443 along with all other Mac services. An optional
root-configured `--model-relay-port=8443` generates, per slot, only a
slot-subnet TCP pass to that slot's IPv4 gateway and that port before the deny rules; a Mac
`pfctl -vnf` syntax-only check rendered the pass and both denies, but **no
model pass rule has been loaded**. Do not set this flag or enable model access
until Gitmoot's mTLS broker and scoped lease are provisioned and the pass
counter, certificate rejection, lease expiry, and unrelated-client denial
are proved on the Mac. Then launch sandboxd with
`--model-relay-listen 0.0.0.0:8443 --model-relay-target 127.0.0.1:43184`.
The relay admits only source addresses in the configured slot IPv4 subnets
(the former `--model-relay-guest-cidr` flag is gone), caps concurrent connections, and forwards to that
one loopback port; Gitmoot's mTLS certificate and short-lived lease still
authorize each model request. Source admission is not a firewall for other
Mac services. Recheck the actual network subnet after any Apple network
recreation. A dummy broker round-trip passed, but no production PF rule,
real model lease, or production relay was enabled.

## Operating the PF helper

Releases are built only by GitHub Actions (`.github/workflows/release.yml`)
from a `vX.Y.Z` tag on `main`. Each release page lists the SHA-256 of
`sandboxd-<tag>-darwin-arm64.tar.gz`, which holds `sandboxd` and
`sandboxd-pf-helper`.

### First install

Create the slot networks first (above). Open the release page in your own
browser, copy the archive's SHA-256, and run from the worker account (the
account that owns the Apple container service; `sudo` tells the helper its
UID, GID and home):

```sh
sudo sh -c 'set -e; d=$(mktemp -d /var/root/sandboxd.XXXXXX); cd "$d"; curl -fsSLO https://github.com/gitmoot/sandboxd/releases/download/<tag>/sandboxd-<tag>-darwin-arm64.tar.gz; echo "<sha256>  sandboxd-<tag>-darwin-arm64.tar.gz" | shasum -a 256 -c; tar -xzf sandboxd-<tag>-darwin-arm64.tar.gz; ./sandboxd-pf-helper install; cd /; rm -rf "$d"'
```

`install` refuses to run from a directory that anyone but root could write
(hence `/var/root`), and refuses root itself or a missing `SUDO_*` identity as
the worker. It then:

- takes as slots every Apple network labelled
  `gitmoot.sandboxd.network=apple-v1` in `hostOnly` mode, in name order, with
  the subnet, gateway and IPv6 prefix Apple reports; it refuses if there is
  none or any fails the `--slot` rules;
- records the SHA-256 of the **current** `pfctl -sr` output as the reviewed
  main ruleset. Compare the printed hash with the reviewed one, or pass
  `--main-rules-sha256 <hash>`; other flags: `--worker-id` (default
  `mac-local`), `--pin-image` (default the reviewed Alpine digest),
  `--container-cli`, `--model-relay-port` (default `0`, deny-only);
- stops a helper started by hand from a Terminal
  (`/usr/local/libexec/sandboxd-pf-helper-<commit>`); that Terminal can be
  closed afterwards;
- installs itself as `/usr/local/libexec/sandboxd-pf-helper` and the
  release's `sandboxd` as `/usr/local/libexec/sandboxd` (root:wheel, 0755);
- runs, from then on, every `container` command as the worker inside the
  worker's own launchd session: `launchctl asuser <uid> /usr/bin/sudo -n -H
  -u #<uid> -g #<gid> -- container …`. Apple's container API server is a
  per-user launchd agent that a system daemon can't reach directly. This
  needs the stock `root ALL=(ALL) ALL` sudoers rule (or any rule letting
  root run commands as the worker without a password); with a sudoers that
  denies it, every arm fails with sudo's message in the helper log;
- writes `/Library/LaunchDaemons/org.gitmoot.sandboxd-pf-helper.plist`
  (starts at boot, restarted if it exits) and loads it, replacing a loaded
  job;
- writes `/usr/local/bin/sandboxd-helper-update`, unless `/usr/local/bin` or
  a directory above it is a symlink or writable by anyone but root (as when
  Homebrew owns it);
- waits for the helper socket and prints the slots (the `--slot` flags
  `sandboxd` needs), the rules hash and the version.

Rerun the same one-liner (with the current release) after recreating slot
networks, changing the reviewed PF main rules, or changing an install flag.

### Updates

```sh
sudo sandboxd-helper-update                    # the latest release
sudo sandboxd-helper-update --version v0.6.0   # a specific one, even older
```

Without `/usr/local/bin/sandboxd-helper-update`, run
`sudo /usr/local/libexec/sandboxd-pf-helper update`. The update fetches the
release from GitHub only, never from the agents' server, and installs it only
if it was published by `github-actions[bot]`, is neither a draft nor a
pre-release, its assets are exactly this release's download URLs, the archive
matches the release's `SHA256SUMS`, and the archive holds exactly the two
binaries as regular files. It says `already up to date` for the installed
version and refuses a "latest" release older than the installed one unless
`--version` asks for it. It refuses while any sandboxd guest VM is running
(pin VMs do not count), because restarting the helper fails sandboxd's gate.
It replaces both binaries, restarts the service
(`launchctl kickstart -k`), waits for the socket and prints
`<old> -> <new>`. Restart `sandboxd` afterwards to run its new binary.
Check the running version with `/usr/local/libexec/sandboxd-pf-helper version`.

### Logs, stop, uninstall

```sh
tail -f /Library/Logs/sandboxd-pf-helper.log
sudo launchctl print system/org.gitmoot.sandboxd-pf-helper
```

Stop it until the next boot with
`sudo launchctl bootout system/org.gitmoot.sandboxd-pf-helper`; start it
again with
`sudo launchctl bootstrap system /Library/LaunchDaemons/org.gitmoot.sandboxd-pf-helper.plist`.
Stop `sandboxd` first: without the helper its gate fails and it stops guests.
To uninstall, stop it, then:

```sh
sudo rm /Library/LaunchDaemons/org.gitmoot.sandboxd-pf-helper.plist \
  /usr/local/libexec/sandboxd-pf-helper /usr/local/libexec/sandboxd \
  /usr/local/bin/sandboxd-helper-update
```

Stopping the helper does not by itself remove its PF anchor; inspect it with
`sudo pfctl -a com.apple/gitmoot-sandboxd -sr`.

Unsupported: template builds, pause/resume, arbitrary E2B envd RPCs, public guest hosts without private authentication, guest inbound ports, snapshots, E2B dollar billing, arbitrary upload paths/users, and executing review policy in the worker. Linux ARM64 OMP upload and scoped model access are separate integration/security requirements, not implied by this HTTP conformance result.
