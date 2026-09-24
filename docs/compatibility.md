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

The selected root-owned PF helper (`cmd/sandboxd-pf-helper`) is a **local
implementation, not yet installed or validated on the Mac**. Its launchd
configuration must fix the dedicated worker UID/GID and HOME, worker ID,
root-owned `container` CLI, `sandboxd-internal` network, trusted pin image at
an OCI digest, IPv4 gateway and subnet, IPv6 ULA prefix, SHA-256 of reviewed
`pfctl -sr` output, and a socket under a root-owned non-writable directory.
It checks the network label/mode, a read-only capability-dropped pin VM,
unique live bridge, PF enabled and not skipping that interface, unchanged
main rules, and the exact IPv4/IPv6 deny anchor before admitting work. Arm
requires no other VM attached and clears old PF states only on that bridge.
`sandboxd` requires the same pin digest through `--pin-image` and the helper
socket through `--pf-socket`; it stops
ordinary guests on gate failure and only requests anchor removal after every
VM has been deleted.
The helper deliberately leaves the deny anchor in place on crash. The digest
image must be provisioned first; the existing tagged Alpine cache was not
available by digest. Neither launchd installation nor a live root-helper,
full deny, egress, reboot, or failure-mode canary has been completed.

The optional fixed model relay transports TLS bytes without terminating TLS
or handling credentials. Gitmoot's mTLS broker listens on its own
`127.0.0.1:8443` and advertises `https://192.168.128.1:8443`, so its server
certificate names the address seen by the guest. A supervised SSH reverse
forward from that broker to the Mac binds only Mac `127.0.0.1:43184`:
`ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:43184:127.0.0.1:8443 jerry@<Mac-tailnet-IP>`.
Only after a Mac admin installs and proves the root helper's firewall policy
and a real mTLS model lease exists, launch sandboxd with
`--model-relay-listen 0.0.0.0:8443 --model-relay-target 127.0.0.1:43184 --model-relay-guest-cidr 192.168.128.0/24`.
The relay admits only guest
subnet source addresses, caps concurrent connections, and forwards to that
one loopback port; Gitmoot's mTLS certificate and short-lived lease still
authorize each model request. Source admission is not a firewall for other
Mac services. Recheck the actual network subnet after any Apple network
recreation. A dummy broker round-trip passed, but no production PF rule,
real model lease, or production relay was enabled.

Unsupported: template builds, pause/resume, arbitrary E2B envd RPCs, public guest hosts without private authentication, guest inbound ports, snapshots, E2B dollar billing, arbitrary upload paths/users, and executing review policy in the worker. Linux ARM64 OMP upload and scoped model access are separate integration/security requirements, not implied by this HTTP conformance result.
