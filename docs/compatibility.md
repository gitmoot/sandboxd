# E2B API compatibility

sandboxd serves two template profiles. The table below is the `gitmoot-strict` profile: the subset Gitmoot's pinned client uses, served by both the Apple and the Firecracker worker. The `e2b` profile, which the stock E2B SDKs use, is served by the Firecracker worker only and is described from [Template registry and profiles](#template-registry-and-profiles) on; [conformance-matrix.md](conformance-matrix.md) has its per-test SDK results.

Client revision: `gitmoot/gitmoot@a61e1435e7625bf062e05eed21337765833eade6` (the build running in production since 2026-10-01; the earlier pin `10f31189` is not available upstream), package `internal/execbackend/e2b`. This is a **subset**, not an E2B SDK implementation. The client fixture tests at that revision are the reference for malformed responses, redirects, truncated streams, and ambiguous failures. The opt-in `TestSandboxdPinnedClientConformance` (`sandboxd_conformance_test.go`) in that same package exercises the actual client against sandboxd and a real VM; it passed on Apple container 1.4.1 over a private SSH tunnel on 2026-09-24, using a temporary key. On 2026-09-30 it passed again through the private Tailscale Serve HTTPS gateway with header routing ([#6]).

| Plane | Supported operation | Authentication and result |
| --- | --- | --- |
| Control | `POST /sandboxes` | `X-API-Key`; known template, secure mode, bounded TTL and owner metadata; `201` with `sandboxID`, `envdAccessToken` and VM shape. Unknown template and unsupported options are rejected. A template that no enrolled worker can run on its architecture is `400`. When every compatible worker is full the answer is `409` `{"code":409,"message":"sandbox capacity exhausted: ..."}`, and nothing was allocated. |
| Control | `GET /sandboxes/{id}` | `X-API-Key`; `200` for live VM; per-ID `404` remains **inconclusive** to the pinned Gitmoot client; unavailable observation is `503`. |
| Control | `GET /v2/sandboxes?limit=100&nextToken=...` | `X-API-Key`; sorted stable-ID pages, `X-Next-Token` and `X-Total-Running`; inventory failure is `503`, never an empty success. The complete inventory, not a per-ID 404, proves absence. Sandboxes of every enrolled worker are merged; an offline or no-longer-enrolled worker's last known running sandboxes stay listed and its ID is named in `X-Sandboxd-Offline-Workers`. |
| Control | `GET /sandboxd/capacity` | `X-API-Key`; sandboxd extension. `200` with `totalSlots`, `usedSlots`, `freeSlots` over online workers, per-template totals, and per-worker `arch`, `driver`, `templates`, `refusedTemplates` (for example an architecture mismatch), `enrolled`, `online`, `lease`, `maxVMs`, `usedSlots`, `cpus`, `memoryMiB`, `lastSeen` and last `error`. |
| Control | `POST /sandboxd/workers/{id}/forget` | `X-API-Key`; sandboxd extension, body `{"confirm":true}`. Releases a non-online worker's live reservations as `unverified` (see [Multiple workers](#multiple-workers)); `409` while the worker is enrolled and online. |
| Control | `POST /sandboxes/{id}/timeout`, `DELETE /sandboxes/{id}` | `X-API-Key`; bounded extension, idempotent confirmed destroy; success `204`; uncertain cleanup is `503` and retains capacity. |
| Control | `GET /sandboxes/{id}/metrics` | `X-API-Key`; measured CPU and memory values from Apple VM stats; `200` array or `503` on incomplete samples. No invented disk usage or cloud charge. |
| Guest | `POST /files?username=user&path=/home/user/...` | `X-Access-Token` per-VM capability and sandbox ID/port routing headers; bounded regular file, confined path, no host mounts. |
| Guest | `POST /process.Process/Start` | Same capability; Connect JSON framed start/data/end messages, flushed stdout/stderr, exit status; combined stdout/stderr capped at 64 MiB per process stream, with VM teardown on overflow; no stdin or unsupported process RPCs. |

The guest endpoint accepts either the private wildcard host `49983-<id>.<domain>` or an explicitly configured single gateway host with `E2b-Sandbox-Id` and `E2b-Sandbox-Port: 49983`. The latter requires Gitmoot's explicit `e2b_envd_base_url` and `provider = "mac"` configuration. The control endpoint is separate from the guest address. Both require private HTTPS in deployment; loopback HTTP was used only for local conformance through an SSH tunnel.

## Template registry and profiles

Templates are registered by the operator only: `-template`/`-image` for a local driver's primary template, `-template-arch <template>=arm64|amd64` for templates served by enrolled workers, and the repeatable `-register-template id=<id>[,arch=arm64|amd64][,image=<image>][,profile=gitmoot-strict|e2b][,alias=<name>]...[,envd-version=X.Y.Z]`. Clients name a template or an alias, never an image. A registration with an image is also served by the local driver (or declared by a `-worker-key-file` worker, which uses only its ID and image), and a local driver's image allowlist is exactly those images. Enrolled workers still declare their own images, and templates are still scheduled by architecture, worker capacity and lease. Each sandbox row records its template's profile:

- `gitmoot-strict` (the primary template, and any further strict ones): the table above, byte for byte. With no `e2b` template registered every response, including error bodies, ID-ordered list pages and the plain `404` for `POST /v2/sandboxes`, is unchanged.
- `e2b` (the general SDK surface, M1 of [#21](https://github.com/gitmoot/sandboxd/issues/21)): `POST /v2/sandboxes` (unknown template `404`; owner metadata optional, and the job fence applies only when `job_id` is present; `autoPause`, `autoResume`, `secure:false`, network and internet options, MCP, IAM and volume mounts are refused with `501`, see [Not supported](#not-supported)), `POST /v2/sandboxes/{id}/connect` (returns the same `envdAccessToken`, an HMAC of the sandbox ID under the 0600 `-token-secret-file`, and only ever extends the timeout within `-max-ttl`, even against concurrent extensions; `set_timeout` sets it as asked, shorter or longer, as on E2B), `GET /sandboxes/{id}` with `clientID` and the template's semver `envdVersion`, `GET /sandboxes/{id}/metrics` with `timestamp`, `memCache`, `diskUsed` and `diskTotal` (a `503` from drivers that do not measure disk and page cache; the Apple and Firecracker drivers do not yet), `DELETE` (a second kill is `404`), and E2B JSON errors `{code, message}`. The envd `GET /health` answers `204` for a live sandbox and its token and `502` otherwise. Pause, resume and snapshots are refused (see [Not supported](#not-supported)); [logs](#sandbox-logs) are served.

### Sandbox logs

`GET /v2/sandboxes/{id}/logs` (`cursor` in Unix ms, `limit` 0–1000 with default 1000, `direction` `forward`|`backward`, `level` minimum, case-sensitive `search`) and the deprecated `GET /sandboxes/{id}/logs` (`start`, `limit`; `logs` and `logEntries`) serve a running `e2b` sandbox's guest console, authenticated by `X-API-Key`. envd runs with `-verbose`, so the console carries its structured logs; each line is one entry stamped with the host time it arrived (the guest's own timestamps are not trusted). envd's JSON lines give `level`, `message` and their scalar fields as strings (plus `source: envd`); nested values, such as the RPC request bodies envd logs at debug level, which can carry a command's environment, are never served. Other lines are `info` entries. The worker keeps at most 1 MiB of console per sandbox (newest lines, each cut at 16 KiB), in memory only, and drops it with the VM: logs of an ended sandbox are `404`. A strict sandbox is `409`. A sandbox whose worker keeps no console (it restarted since the sandbox started, or Firecracker runs with `ConsoleLog`, which sends the console to `<jail>/console.log` instead) answers `501`. Enrolled workers serve the console at `GET /worker/v1/vms/{id}/console`.

### Not supported

Once an `e2b` template is registered, every route of an unsupported E2B feature answers `501` with E2B's error body `{"code":501,"message":"<reason>; see docs/compatibility.md#not-supported"}`: never a `404` route miss or a silent success, and nothing is changed. The SDKs raise their generic API error with that text, `501: <reason>; …` (Python `SandboxException` with `status_code == 501`, `VolumeException`, `SecretException` or `BuildException`; JS `SandboxError` with `statusCode === 501`, `VolumeError`, `SecretError` or `BuildError`). A per-sandbox action (pause, resume, snapshot, fork, network) on a sandbox that is gone or unknown is still the `404` the SDKs raise as not found, as on E2B. A strict-only service keeps its plain `404`. The stock-SDK tests in `conformance/sdk` assert each SDK-visible error exactly.

| Feature | Requests | Reason |
| --- | --- | --- |
| Pause, resume, auto-pause | `POST /sandboxes/{id}/pause`, `POST /sandboxes/{id}/resume`; create with `autoPause:true` or `autoResume` | `pause and resume are not supported: sandboxd never pauses a sandbox (deferred, owner decision D7)`; create: `autoPause (pause and resume) is not supported`, `autoResume is not supported` |
| Snapshots | `POST /sandboxes/{id}/snapshots`, `GET /snapshots` | `snapshots are not supported: sandboxd keeps no sandbox state after a sandbox ends (deferred with pause, D7)` |
| Snapshot or template delete | `DELETE /templates/{id}` | `deleting templates or snapshots through the API is not supported: …` |
| Fork | `POST /sandboxes/{id}/fork` | `fork is not supported: it needs snapshots (deferred with pause, D7)` |
| Network updates and options | `PUT /sandboxes/{id}/network`; create with `allow_internet_access`, or `network` other than exactly `{"allowPublicTraffic":false}` (what sandboxd always does) | `network updates are not supported: a sandbox's network policy is fixed by the operator`; create: `network and internet access options are not supported (guest ports are never public: only network.allowPublicTraffic=false is accepted)` |
| Volumes | `/volumes`, `/volumes/{id}`; create with `volumeMounts` | `volumes are not supported: sandboxd keeps no storage beyond a sandbox's lifetime`; create: `volume mounts are not supported` |
| Secrets | `/secrets`, `/secrets/{id}` | `secrets are not supported: pass values to a sandbox in envVars instead` |
| MCP gateway | create with `mcp` | `MCP gateways are not supported` |
| IAM | create with `iam` | `IAM options are not supported` |
| Teams | `/teams…` | `teams are not supported: sandboxd has a single operator API key` |
| Template build and management (D8) | `/v3/templates`, `/v2/templates…`, `/templates…` (builds, files, status, logs, tags) | `template builds and template management through the API are not supported: the operator builds and registers templates with the sandboxd CLI (D8)` |
| `secure:false` | create | `every sandbox requires its envd access token; secure=false is not supported` |

`GET /templates/aliases/{alias}` (the SDKs' `Template.exists`) is supported: a registered template ID or alias is `200` `{"templateID","public":false}`, anything else `404`.

### e2b data plane (upstream envd, M2 of [#21](https://github.com/gitmoot/sandboxd/issues/21), [#25](https://github.com/gitmoot/sandboxd/issues/25))

An `e2b` guest runs upstream [E2B envd](https://github.com/e2b-dev/infra) (Apache-2.0, pinned to 0.9.0; `images/e2b-amd64-fc`, `images/e2b-arm64`, see [firecracker.md](firecracker.md#e2b-base-image)) as its entrypoint, with a writable root as E2B provides. Register such templates with `envd-version=0.9.0`.

- **Ingress.** sandboxd stays the only ingress. For an `e2b` sandbox it forwards, to the guest's envd only, `/process.Process/<Method>`, `/filesystem.Filesystem/<Method>` (method names matching `^[A-Z][A-Za-z0-9]*$`; a path with any percent-encoded byte, or a `.`/`..` segment, is never forwarded), `/files` (GET/POST, multipart, octet-stream, gzip), `/files/compose`, `/envs` and `/health`, after checking the sandbox's `X-Access-Token` itself (a missing or wrong token is `401`, and `/health` of a sandbox that is not running is `502`). A `GET`/`POST /files` without a token is accepted only with a valid, unexpired E2B v1 URL signature made with that token (`download_url`/`upload_url`). envd's internal routes (`/init`, `/freeze`, upgrades, ...) are never forwarded. Connect streaming, client streams and half-close pass through unbuffered. `gitmoot-strict` sandboxes keep the original `internal/envd` handler byte for byte; neither profile's token opens the other's data plane.
- **Channel.** The proxy reaches envd only over the worker's host-initiated channel, never the guest network: on Firecracker a fresh vsock connection to the guest agent, which bridges it to envd on the guest loopback (the driver's firewall monitor watches it while it is open, as it does running commands); through an enrolled worker an authenticated `POST /worker/v1/vms/{id}/ports/49983` HTTP/1.1 upgrade carrying the same stream (see guest ports below); on the dev driver a Unix socket. The Apple driver refuses `e2b` guests until its exec-stdio channel (D10) lands.
- **Create.** After the VM boots, sandboxd sends envd its `/init`: the sandbox's envd access token, default user `user`, working directory `/home/user`, and the create request's `envVars`. `envVars` are held only in that request's memory and the guest; they are never written to the ledger or logged. If envd does not initialize within 30 s the sandbox is destroyed and create answers `503`.
- **Users.** Commands and files default to `user` (1000:1000, home `/home/user`, passwordless `sudo`, as in E2B's base template). SDK `user="root"` is allowed inside the VM (owner decision D3, after the isolation probes in [#25](https://github.com/gitmoot/sandboxd/issues/25) passed): root inside the guest owns only that VM. See [firecracker.md](firecracker.md#root-inside-an-e2b-guest).
- **Metrics.** Firecracker reports page cache from the VMM cgroup's `memory.stat` (`file`) and disk use from the guest agent's `statfs` of the writable filesystem (the home disk, or an `e2b` guest's root), so `get_metrics` no longer answers `503` there. A strict guest booted from an image whose agent predates the disk report keeps its CPU and memory metrics; only `e2b` metrics, which need disk figures, answer `503` for such a guest (`e2b` images always include it).

Once any `e2b` template is registered, `GET /v2/sandboxes` is one account-wide view, as on E2B: it accepts `metadata` (each key and value matches as sent or with the JS SDK's extra URL-encoding undone, so a literal value such as `a%20b` still matches itself), `state`, `template` (ID or alias), `startedAfter` and `order`, lists newest first by default, adds `clientID` to every item, and answers errors as JSON. Completeness stays per profile: a `gitmoot-strict` row that cannot be described still turns a response it belongs to into a `503`, while an `e2b` row never does (one that is not running, or whose template is no longer registered with the `e2b` profile, is simply not listed; a worker that stops declaring a template has its VMs reaped by reconciliation, as for every template). Per-key views are M4.

A guest execution or upload that its caller cancels, or that fails in the
gateway's own (local) driver, revokes its capability and destroys the
**entire VM**, because Apple `container exec` alone leaves the guest process
alive when the host CLI disconnects. On an enrolled remote worker, a call
that fails because the worker is unreachable, the gateway-to-worker stream is
lost, or a newer gateway owns the worker does **not** tear the VM down: it
answers `unavailable` and keeps the VM and its capability (see
[Network blips](#multiple-workers) under Multiple workers). An uncertain
destroy remains reserved as `unknown` for reconciliation. Set
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
upload, not model access or a full PR review. Both were proven later: scoped
model access from guests ([#8]) and a full production review ([#10]).

Security gate: Apple `hostOnly` is **not** a host firewall. Without PF, a
guest reached Mac wildcard listeners over IPv4, IPv6 ULA, and IPv6
link-local, and Mac IPv4 and IPv6 forwarding are enabled. sandboxd therefore
runs no guest work unless the root PF helper below has armed every slot. With
the helper armed on the Mac, three fresh guests could not reach Mac services
(IPv4 and IPv6), the LAN, the tailnet, or the internet ([#3], [#8]).

The root-owned PF helper (`cmd/sandboxd-pf-helper`) runs as a launchd system
service on the production Mac and is approved for Gitmoot's opt-in Mac
provider. Gitmoot routes a job there only when it asks for
`--exec-provider mac`; cloud E2B stays the default ([#9], [#10]).
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
IPv4 subnet to the **first** slot's gateway address (the one relay address)
and that port; both IPv4/IPv6 block rules still follow. Arm loads the
configured anchor into an empty anchor, or replaces the exact deny-only anchor
a relay-off helper loaded for the same attested bridges in slot order (so
enabling the relay needs no manual `pfctl` flush). It refuses any other
unrelated or changed anchor rules, including a deny-only anchor naming other
bridges.
`sandboxd` requires the same pin digest through `--pin-image`, the same
`--slot` list, and the helper socket through `--pf-socket`; it stops
ordinary guests on gate failure and only requests anchor removal after every
VM has been deleted.

### e2b guest ports, `get_host` and signed file URLs (M3, [#26](https://github.com/gitmoot/sandboxd/issues/26))

Guest ports other than envd's are **allowlist-only per template** and **never public** (E2B's `allowPublicTraffic=false`):

- Register the ports with the template: `-register-template id=…,profile=e2b,…,port=49999[,port=…]`. Strict templates cannot expose ports. No other guest port is reachable, and envd's 49983 is never a template port.
- Every request needs the sandbox's traffic access token (`E2b-Traffic-Access-Token`, returned as `trafficAccessToken` by create and connect, HMAC-derived like the envd token with a different label) or its envd access token (`X-Access-Token`). The traffic token opens the template's ports only, never envd. Refusals use E2B's edge bodies: 403 for a missing or invalid token or a port the template does not expose, 502 for an unknown sandbox or a closed port, 429 past `-port-max-streams` concurrent requests per sandbox (default 256; WebSocket and other upgraded streams count while open).
- Routing: on the gateway host (`-gateway-host`) with the SDKs' `E2b-Sandbox-Id`/`E2b-Sandbox-Port` headers, which the code-interpreter SDKs send when `E2B_SANDBOX_URL` points at the gateway. The bytes reach the guest only over the host-initiated channel (Firecracker vsock → guest agent `OpDial` → guest loopback; the worker API's `POST /vms/<id>/ports/<n>` upgrade for enrolled workers); nothing listens on a host port and the guest network is not involved. HTTP, streaming and WebSocket upgrades pass through. When a guest port closes (its server restarts), the guest agent closes the host's stream at once, so the gateway never reuses a dead pooled connection.
- Headers: a guest port is served by untrusted guest code, so sandboxd never forwards its routing headers, the traffic token, `X-API-Key`, `Authorization`, `Cookie` or `Proxy-Authorization` to it (a guest web app cannot use cookies or HTTP authentication through the gateway). `X-Access-Token` does reach the port: E2B's code-interpreter server reads it to call the sandbox's own envd (`/envs`), and it opens nothing but that sandbox's envd. envd gets `X-Access-Token` and `Authorization` (its token check and the Basic user a process or file runs as) and none of the others.
- `create` accepts `network: {"allowPublicTraffic": false}` (what sandboxd always does); every other network option is still refused.
- `get_host(port)` returns `<port>-<id>.<domain>`; the SDKs never apply `E2B_SANDBOX_URL` to it. That form needs wildcard DNS and TLS for `*.<domain>` in front of sandboxd. Owner decision D2 defers wildcard DNS, so host routing of guest ports is **off by default** in `sandboxd` and `sandboxd-dev` and `get_host` URLs do not resolve in a default deployment; the code-interpreter SDKs use the routing headers instead. `-port-hosts` turns host routing on once an operator has both. The token rules are the same; envd's own `49983-<id>.<domain>` host stays routed as before. For a client on the gateway's own machine, a domain under `localhost` (for example `sbx.localhost:<port>`) resolves without DNS setup on resolvers that implement RFC 6761, but still needs a TLS front.
- Signed file URLs (`download_url`/`upload_url`) are built from `E2B_SANDBOX_URL` and carry no routing headers. sandboxd routes a `/files` request with a `signature` on the gateway host to the one running e2b sandbox whose envd token made that signature (the signature binds path, operation, user, expiry and token), so no wildcard DNS is needed. Such a request proves nothing until a signature matches, so a signature of the wrong shape or with an unparsable expiration is refused before any lookup, as is an expired one (envd's own `401 {"code":401,"message":"signature is already expired"}`), and the match reads only an in-memory index of running e2b sandboxes (kept on create, delete, reconcile and restart), never the ledger or the control lock.
- Template start and ready commands: `start-cmd=<command>` runs once per sandbox as root through envd right after `/init`, in the background; `ready-cmd=<command>` then runs as root until it exits 0 before create returns 201. Both together are bounded by `-template-ready-timeout` (default 3m); a sandbox not ready by then is destroyed (503). Give the client's create request a longer timeout than a cold start (the stock SDKs default to 60 s). E2B runs the start command at template build time and snapshots the result; sandboxd has no snapshots, so this is a per-create cold start. The `code-interpreter-v1` image and its registration line are in [firecracker.md](firecracker.md#code-interpreter-image).

### CI conformance gate (dev driver)

Every pull request runs `conformance/run.py` (`.github/workflows/conformance.yml`).
It builds `cmd/sandboxd-dev` with `-tags sandboxd_devdriver` and starts a fresh
instance per suite on loopback. That binary serves the real `internal/control`
and `internal/envd` code with `internal/vm/devvm`, a CI-only driver whose
"VMs" are local process groups in temporary directories: **no isolation**,
no PF helper, no slots. The build tag keeps it out of `cmd/sandboxd` and the
PF helper; `cmd/sandboxd/devdriver_guard_test.go` fails if either links it
or if a dev-driver source builds without the tag.

Against that instance the harness runs, unchanged:

- the upstream Python and JS `e2b` 2.52.0 tests and the code-interpreter
  Python 2.10.1 and JS 2.8.0 tests, from pinned `e2b-dev/E2B` tag commits,
  with the stock SDKs configured only by `E2B_API_URL`, `E2B_SANDBOX_URL`,
  `E2B_API_KEY` and `E2B_DOMAIN`;
- the pinned Gitmoot package `internal/execbackend/e2b`: its offline
  fixture tests and `TestSandboxdPinnedClientConformance`, with
  `SANDBOXD_CONFORMANCE_CANCEL=1`.

The per-test outcomes are recorded in `conformance/expected.json` and rendered
as [`docs/conformance-matrix.md`](conformance-matrix.md), which lists every
expected failure. The gate fails when any recorded outcome changes, in either
direction: a regression fails, and so does an improvement that was not
recorded. Record intended changes with `python3 conformance/run.py --update`
and commit both files. Locally the harness needs `git`, `go`, Python 3.11+ and
Node 22+; it installs the SDKs into a temporary venv and npm directory and
deletes them afterwards unless `--workdir` is given.

This proves the wire contract only. Isolation is proven on a real worker.

**Code-interpreter in CI (M3 decision).** The gate does not boot the
`code-interpreter-v1` image. That image is 3.6 GiB (Jupyter plus Python, R,
Java, Node and bash kernels) and needs a Firecracker worker with KVM, which
GitHub runners do not have. The dev driver cannot serve it either: its
guests have no in-guest server on port 49999. The gate therefore keeps
running the stock code-interpreter suites against the base `e2b` template
and pins their outcomes (the `run_code` tests are recorded failures there).
The acceptance evidence for `code-interpreter-v1` is a run of the same stock
suites against a real Firecracker worker, repeated whenever the image, the
guest agent or the port proxy changes. On 2026-10-05 (image
`code-interpreter-amd64-a5e50c1be0ff`, `-memory-mib 2048`) it gave Python
163 passed / 0 failed and JS 82 passed / 0 failed. A python-only dev-driver
template is feasible: its server and kernel venv measured 429 MB and
installed in 38 s. It would cover only the python kernel and has not been
added.

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

The helper deliberately leaves the anchor in place on crash. On the Mac, the
armed deny-only anchor blocked previously successful guest IPv4, IPv6 ULA,
and link-local connections while unrelated Mac and tailnet traffic kept
working, and per-slot networks blocked guest-to-guest traffic ([#3], [#8]).
Still unverified: live PF rule counters, helper failure while armed, and
recovery after a Mac reboot ([#7]).

The optional fixed model relay transports TLS bytes without terminating TLS
or handling credentials. Gitmoot advertises **one** credential gateway URL
whose server certificate carries one IP SAN, and Apple `container` 1.4.1 has
no `--add-host` for per-guest names, so every slot uses the same relay
address: the **first** slot's gateway, e.g. `https://192.168.128.1:43181`.
A guest on another slot reaches it through its own default gateway and the
Mac delivers it locally; on the Mac, guests in all three slots reached the
relay at the same time ([#8]). Gitmoot's mTLS broker listens on its own
`127.0.0.1:8443`; a supervised SSH reverse forward from that broker to the
Mac (in production, a service on the Gitmoot host) binds only Mac
`127.0.0.1:43184`:
`ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:43184:127.0.0.1:8443 <user>@<mac-host>`.
The default PF anchor blocks the relay along with all other Mac services. An
optional root-configured `--model-relay-port=43181` generates, for every
slot, only a TCP pass from that slot's IPv4 subnet to the first slot's
gateway and that port, before that slot's deny rules. For slots
`192.168.128.0/24`, `192.168.130.0/24` and `192.168.131.0/24` on
`bridge101`..`bridge103` the helper loads (with `-o none`):

```
pass in quick on bridge101 inet proto tcp from 192.168.128.0/24 to 192.168.128.1 port 43181
block in quick on bridge101 inet from any to any
block in quick on bridge101 inet6 from any to any
pass in quick on bridge102 inet proto tcp from 192.168.130.0/24 to 192.168.128.1 port 43181
block in quick on bridge102 inet from any to any
block in quick on bridge102 inet6 from any to any
pass in quick on bridge103 inet proto tcp from 192.168.131.0/24 to 192.168.128.1 port 43181
block in quick on bridge103 inet from any to any
block in quick on bridge103 inet6 from any to any
```

and accepts only this `pfctl -a com.apple/gitmoot-sandboxd -sr` readback:

```
pass in quick on bridge101 inet proto tcp from 192.168.128.0/24 to 192.168.128.1 port = 43181 flags S/SA keep state
block drop in quick on bridge101 inet all
block drop in quick on bridge101 inet6 all
pass in quick on bridge102 inet proto tcp from 192.168.130.0/24 to 192.168.128.1 port = 43181 flags S/SA keep state
block drop in quick on bridge102 inet all
block drop in quick on bridge102 inet6 all
pass in quick on bridge103 inet proto tcp from 192.168.131.0/24 to 192.168.128.1 port = 43181 flags S/SA keep state
block drop in quick on bridge103 inet all
block drop in quick on bridge103 inet6 all
```

Guest-to-guest isolation is unchanged: the only address a guest may reach
is the Mac's own relay address; other slots' gateways and guests stay
denied. On the production Mac this pass rule is loaded (helper v0.1.2,
installed with `--model-relay-port 43181`) and proven: guests in all three
slots, running at the same time, got a real model answer through Gitmoot's
mTLS credential gateway, with no provider key in the gateway or any guest;
a request without the client certificate failed TLS, and a wrong capability
or a revoked lease got `401` ([#8]). Production reviews use this path
([#10]). Reading the live pass counter is still outstanding; it is
diagnostic and does not gate the relay. On any other Mac, set this flag only
once Gitmoot's mTLS broker and scoped lease are provisioned, and repeat those
checks there. Then launch sandboxd with
`--model-relay-listen 192.168.128.1:43181 --model-relay-target 127.0.0.1:43184`;
sandboxd refuses a listen IP other than the first `--slot` gateway. The
relay admits only source addresses in the configured slot IPv4 subnets
(the former `--model-relay-guest-cidr` flag is gone), caps concurrent connections, and forwards to that
one loopback port; Gitmoot's mTLS certificate and short-lived lease still
authorize each model request. Source admission is not a firewall for other
Mac services. Recheck the actual network subnets after any Apple network
recreation.

## Multiple workers

One sandboxd is the gateway. Its own driver (the Mac, configured exactly as
above) is one worker; `-enroll` adds more. `-driver none` runs a gateway with
no local VMs. A remote worker is a sandboxd started with
`-worker-key-file <0600 file>` and its usual driver flags (no `-db`,
`-api-key-file`, `-domain` or `-gateway-host`). It declares its real driver
and architecture: `apple` runs `arm64` guests, `firecracker` runs `amd64`
guests ([firecracker.md](firecracker.md)). It serves only the worker API on
its loopback `-listen` address, behind a private HTTPS proxy such as
Tailscale Serve, exactly like the control API:

```sh
sandboxd ... -enroll id=linux-1,url=https://linux-1.<tailnet>:8444,key-file=/etc/sandboxd/linux-1.key \
  -template-arch review-amd64=amd64
```

- **Declaration.** On enrollment each worker declares its ID, guest
  architecture, driver, templates (template ID to worker-local image), VM
  shape and slots. `-template-arch` registers each template served by
  enrolled workers with the architecture it needs; the local template needs
  the local architecture. A template declared by a worker of another
  architecture is refused and reported under `refusedTemplates`.
- **Authentication.** Each worker has its own key (at least 16 bytes), sent
  as a bearer token over HTTPS; plain HTTP is accepted only to a loopback
  IP. A worker that answers with another worker's ID is refused.
- **Scheduling.** A create goes to the online worker that serves its
  template and has the most free slots. Slots and capacity are per worker.
  When every compatible worker is full, create is `409` as above.
- **Fencing.** A gateway instance claims each worker once, with a new lease
  from a durable per-worker counter in the ledger, and keeps that lease
  across reconnects. A worker refuses requests made under an older lease and
  cancels runs, uploads and creates started under one, so only a newer
  gateway instance (a restart, or one whose ledger was replaced) fences an
  older one. A superseded gateway stops using the worker until it restarts;
  it destroys nothing there. Each row records its worker and the lease under
  which it was last proven present.
- **Network blips.** While a worker cannot be observed, its sandboxes grant
  no new guest access and it gets no new work, but its lease is kept: when it
  answers again it is re-enrolled under the same lease, and runs already in
  flight continue. A guest call that fails because the worker is unreachable,
  the stream was lost, or a newer gateway owns the worker answers
  `unavailable` and keeps the VM; only a real guest failure, an output
  overflow or the caller's own cancellation tears the VM down. (After a lost
  stream the guest process may still be running; the job can retry or delete
  the sandbox, and the worker's expiry bounds it.) Every gateway-to-worker
  call has a deadline (10 s; 3 min for a create or a requested destroy), the
  worker client bounds dialing, the TLS handshake and the wait for response
  headers, and each worker is reconciled on its own, so one stalled worker
  never holds up renewals, the sweep or the other workers.
- **Upgrades.** The gateway and its workers are upgraded together. M3 (#26)
  replaced the worker API's envd-only stream (`POST /vms/{id}/envd`) with
  guest port streams (`POST /vms/{id}/ports/{port}`, upgrade token
  `sandboxd-port`) and the guest agent's `OpEnvd` with `OpDial`, with no
  compatibility path: an older worker refuses the new gateway's streams, and
  an image whose agent predates `OpDial` serves no e2b guest traffic. No
  remote worker ran the old protocol, so none was needed.
- **Expiry on the worker.** The gateway sends each sandbox's end time to its
  worker on create, on renewal (`POST /sandboxes/{id}/timeout` fails with
  `503` if the worker cannot be told) and after every re-enrollment. The
  worker caps it by its own `-max-ttl` and destroys expired VMs itself every
  second, also while partitioned from the gateway or after `forget-worker`.
  A VM a restarted worker finds without an end time gets `-max-ttl` from then.
- **Losing a worker.** Its sandboxes stay in the ledger, keep their slots and
  are listed as unconfirmed; deleting one is `503` until the worker returns.
  A retried job is scheduled elsewhere; when the old worker returns, its
  superseded attempt is destroyed and every other sandbox is kept. The other
  workers' sandboxes are not affected.
- **Removing a worker.** A worker whose `-enroll` is removed while it still
  owns live sandboxes is treated like an offline one: its sandboxes stay
  listed, it is named in `X-Sandboxd-Offline-Workers` and reported in
  capacity with `"enrolled": false`, deletes are `503`, and its reservations
  count only against itself, so the other workers keep admitting. (An
  identity that ran on the gateway's own host, such as a renamed local
  worker, still holds the local slots its VMs may occupy.)
- **Forgetting a worker.** When a worker is gone for good, release its
  reservations explicitly:

  ```sh
  sandboxd forget-worker -id linux-1 -confirm -api-key-file <key> [-api-url http://127.0.0.1:43180]
  ```

  This calls `POST /sandboxd/workers/{id}/forget` with `{"confirm":true}`. It
  is refused (`409`) while the worker is enrolled and online. Its live rows
  become `unverified`, a state distinct from `gone`: their VMs were not proven
  destroyed, and the gateway and the command log each sandbox ID as such.
  They no longer hold capacity and are not listed. If the worker is enrolled
  again, its complete inventory destroys their VMs and only then are the
  rows marked `gone`.

## Review image module cache

Guests have no network egress, so Go cannot download modules inside a review.
The review image (`images/linux-arm64/Dockerfile`) therefore bakes a
pre-downloaded module cache at `/opt/gomodcache`, outside the `/home/user`
volume, root-owned and read-only to uid 1000. A throwaway build stage fetches
each repository in `GOMOD_REPOS` at a pinned commit (no credentials; public
repositories only), runs `go mod download all` plus
`go list -deps -test ./...` in every module (and at a `go.work` root), then
checks the result offline with `go mod verify` and `GOPROXY=off go list`.
Only the cache is copied into the final image; the clones are discarded.

The image sets `GOMODCACHE=/opt/gomodcache GOPROXY=off GOSUMDB=off
GOFLAGS=-mod=readonly GOTOOLCHAIN=local`. `go.sum` is still enforced: a
changed hash fails with `checksum mismatch` and a missing entry with
`missing go.sum entry`. The build cache (`GOCACHE`) stays on the writable
`/home/user` volume.

Rebuild rule: the cache matches the pinned commits only. A review of a branch
whose `go.mod`/`go.sum` adds or bumps a module fails offline (for example
`mkdir /opt/gomodcache/cache/download/...: read-only file system`, or
`missing go.sum entry`). After any listed repository's `main`
changes its module graph (or the Go toolchain changes), bump its commit in
`GOMOD_REPOS`, rebuild on the Mac under a new local tag, and point
`sandboxd --image` at that tag. Pass `--build-arg GOMOD_REPOS=...` for a
one-off build; commit the new pins so the image stays reproducible.

To add a repository routed to the Mac, append
`https://github.com/<owner>/<repo>@<full 40-character commit>` to
`GOMOD_REPOS`. It must build with the image's Go version under
`GOTOOLCHAIN=local`; the image build fails if any of its modules cannot be
downloaded, verified, or resolved offline.

## Operating the PF helper

Releases are built only by GitHub Actions (`.github/workflows/release.yml`)
from a `vX.Y.Z` tag on `main`. Each release page lists the SHA-256 of
`sandboxd-<tag>-darwin-arm64.tar.gz`, which holds `sandboxd` and
`sandboxd-pf-helper`, and of the Linux tarballs
([firecracker.md](firecracker.md#from-a-release)).

### Guest egress

Guests reach the public internet over IPv4, like E2B; the Linux worker does
the same (docs/firecracker.md). The helper's anchor `com.apple/gitmoot-sandboxd`
holds, in this order:

- three tables: `<sandboxd_deny>` (const), the shared Go list in
  `internal/egress` that the Firecracker driver also uses: `0/8, 10/8,
  100.64/10` (CGNAT and Tailscale), `127/8, 168.63.129.16/32` (Azure
  WireServer), `169.254/16, 172.16/12, 192.168/16, 224/3, ::/127,
  ::ffff:0:0/96, 64:ff9b::/96, fc00::/7, fe80::/10, ff00::/8`, plus every
  `--deny-cidr`; `<sandboxd_host>`, every destination the Mac itself
  receives on: each address on every interface (LAN, Tailscale, loopback,
  bridges, any public address), each IPv4 subnet's broadcast,
  `255.255.255.255` and `224/4`. Each check and, while the anchor is loaded,
  the helper itself every 5 s bring it up to date; `<sandboxd_guests>`
  (const), the slot subnets;
- one `nat on <egress> inet from <slot subnet> to any -> (<egress>)` per slot.
  `<egress>` is `--egress-interface`, or the Mac's default route interface
  when sandboxd arms (restart sandboxd after the default route moves);
- per slot bridge: the model relay pass (if enabled) to the first slot's
  gateway on its one port; block to `<sandboxd_deny>`; block to
  `<sandboxd_host>`; pass from the slot's own subnet to anything else; block
  all other IPv4 and all IPv6;
- then, for every other interface: block anything for a guest subnet, and,
  only while the helper guards forwarding (below), pass DHCP replies
  (`udp` from port 67 to port 68, sent to an address the Mac does not have
  yet) and then
  `block in quick on ! lo0 inet from any to ! <sandboxd_host>`. Slot bridge
  packets never get this far, so then the only IPv4 the Mac forwards is
  guest NAT egress: a LAN, VPN or Tailscale host that uses the Mac as its
  gateway is not routed anywhere, except for UDP from port 67 to port 68.

So a guest never reaches private networks, the Mac (every port except the
relay's, including its resolver) or another guest, in either direction.
Guests use the public resolvers `1.1.1.1` and `8.8.8.8` (`container create
--dns`). The check requires `nat-anchor "com.apple/*"` in `pfctl -sn` (stock
macOS has it), exact filter and NAT readback, and exact deny and guest tables.

**IPv4 forwarding.** Guest NAT needs `net.inet.ip.forwarding=1`. The helper
keeps a record in `/var/run/sandboxd-pf/ip-forwarding-before-arm` (beside
the socket; macOS clears it at boot, when the sysctl resets too):

- **`1`, the operator's forwarding:** forwarding was on at the first arm, for
  example on a Tailscale exit node or subnet router, or with OrbStack or
  Internet Sharing. The anchor has no catch-all, so that routing works
  exactly as before; every guest rule and the block of other interfaces
  reaching guest subnets stay. An exit-node or OrbStack Mac keeps working.
- **`0`, the helper's forwarding:** forwarding was off when the helper
  needed it, at the first arm or later (the operator stopped routing while
  sandboxd ran; the next arm, check or refresh finds it off). From then on the
  helper owns it: it records `0`, loads the catch-all, turns forwarding on and
  restores it at disarm.

While the helper owns forwarding, every arm, every check and the helper's
own refresh (every 5 s while the anchor is loaded) look for evidence of
another forwarder: a `nat`, `rdr` or `binat` rule in `pfctl -sn` outside
the helper's anchor, in the main ruleset or in any anchor it calls, including
every anchor under `com.apple` (`pfctl -a com.apple -v -s Anchors`, then
`pfctl -a <anchor> -sn`), where Internet Sharing and vmnet shared (NAT)
networks put their NAT. A bridge with an IPv4 address is not evidence:
vmnet host-only networks have one too and forward nothing. With evidence
the catch-all is dropped, and it comes back when the evidence goes; the
helper logs each change. Check reloads the anchor in place, so sandboxd sees
no gap. Disarm (sandboxd's clean shutdown, after its guests are gone) turns
forwarding off if the record says `0` and there is no evidence, logs when it
leaves it on, then removes the record. When in doubt (an anchor that cannot
be read) the helper finds no evidence and keeps the guard: a needless guard
only costs another forwarder availability, while a missing guard would make
the Mac an unguarded router. IPv6 forwarding is never touched.

Forwarding follows PF enforcement. The helper turns forwarding on only while
PF is enabled, the reviewed main ruleset calls `com.apple/*` for filter and
NAT, and the anchor's filter and NAT read back as one of its own shapes. If
that stops holding (`pfctl -d`, a replaced main ruleset, a flushed anchor)
while the helper owns forwarding, the next check or refresh turns forwarding
off and logs a `SECURITY:` line; check also fails, so sandboxd stops guest
work. Forwarding the operator had on (record `1`) is never turned off.

Limits: a forwarder that leaves no translation rule (a VPN client relying on
plain routing, a routing-only setup) is not detected. If it starts after the
helper took forwarding, the catch-all drops its forwarded traffic, and disarm
turns forwarding off. Turn forwarding on before starting `sandboxd` (record
`1`) to keep such routing. The DHCP pass allows any UDP packet from port 67
to port 68 through the Mac. The refresh reconciles only while every slot
bridge is up; without them no guest can run.

`internal/firewall/testdata/egress-3slot-forwarding-{off,on}.*` are the
generated rulesets for the three-slot Mac. A per-slot deny-all mode exists in
the generator for `allow_internet_access:false` (M4) but is not reachable
from the API yet.

Guest egress needs a new helper release: the owner installs it with
`sudo sandboxd-helper-update`, then restarts `sandboxd`. Its first arm
replaces the old deny-all anchor in one `pfctl` load. To add a deny prefix
(e.g. a provider's metadata endpoint on a public address) or pin the NAT
interface, rerun `install` with `--deny-cidr <prefix>` or
`--egress-interface <if>`.

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
  `--container-cli`, `--model-relay-port` (default `0`, no relay exception),
  `--deny-cidr` (repeatable) and `--egress-interface` (see Guest egress);
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
networks, changing the reviewed PF main rules, or changing an install flag,
or rerun the installed helper itself, which keeps all of the checks above and
replaces its own binary by rename.

### Enabling the model relay

Once the relay may be enabled (see the model relay section), with no guest
VMs running:

```sh
sudo sandboxd-helper-update
sudo /usr/local/libexec/sandboxd-pf-helper install --model-relay-port 43181
```

Pass the same `--worker-id`, `--pin-image`, `--container-cli` or
`--main-rules-sha256` as the first install if you changed them there. Then
restart `sandboxd` with
`--model-relay-listen <first slot gateway>:43181 --model-relay-target 127.0.0.1:43184`.
Its startup arm replaces the deny-only anchor with the relay policy in one
`pfctl` load; until then the helper's check refuses the deny-only anchor, so
a `sandboxd` still running from before stops guest work.

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
A clean `sandboxd` stop disarms, which removes the anchor and restores IPv4
forwarding (above); if `sudo pfctl -a com.apple/gitmoot-sandboxd -sr` still
shows rules, `cat /var/run/sandboxd-pf/ip-forwarding-before-arm` and, if it
says `0`, run `sudo sysctl -w net.inet.ip.forwarding=0` after flushing the
anchor. To uninstall, stop it, then:

```sh
sudo rm /Library/LaunchDaemons/org.gitmoot.sandboxd-pf-helper.plist \
  /usr/local/libexec/sandboxd-pf-helper /usr/local/libexec/sandboxd \
  /usr/local/bin/sandboxd-helper-update
```

Stopping the helper does not by itself remove its PF anchor; inspect it with
`sudo pfctl -a com.apple/gitmoot-sandboxd -sr`.

Unsupported: template builds, pause/resume, arbitrary E2B envd RPCs, public guest ports (every guest port needs a token and a template allowlist entry; see the e2b guest ports section), snapshots, E2B dollar billing, arbitrary upload paths/users, and executing review policy in the worker. Linux ARM64 OMP upload and scoped model access are separate integration/security requirements, not implied by this HTTP conformance result; both were proven separately on the Mac ([#6], [#8], [#10]).

[#3]: https://github.com/gitmoot/sandboxd/issues/3
[#6]: https://github.com/gitmoot/sandboxd/issues/6
[#7]: https://github.com/gitmoot/sandboxd/issues/7
[#8]: https://github.com/gitmoot/sandboxd/issues/8
[#9]: https://github.com/gitmoot/sandboxd/issues/9
[#10]: https://github.com/gitmoot/sandboxd/issues/10
