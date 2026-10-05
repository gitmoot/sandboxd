# Root filesystem of the Firecracker review guest (linux/amd64). build.sh
# exports this image into a read-only ext4 file; it never runs as a container.
# Same guest contract as images/linux-arm64 (review-arm64): the tools of its
# golang:bookworm base (git, openssh-client, procps, wget, curl), plus
# bash, a C toolchain and python3, user 1000:1000 with home /home/user. Go
# and the module cache are not included yet.
FROM --platform=linux/amd64 debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl e2fsprogs git make gcc g++ python3 tar gzip unzip \
    netbase openssh-client procps wget xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 user \
    && useradd --uid 1000 --gid 1000 --home /home/user --create-home --shell /bin/sh user \
    && mkdir -p /etc/sandboxd

# PID 1: mounts the guest filesystems, formats the per-VM home disk and
# serves exec and file writes over vsock (cmd/sandboxd-guest-agent).
COPY sandboxd-guest-agent /sbin/sandboxd-agent

# The image environment, applied to every guest command (Dockerfile ENV is
# lost by the export). Request variables replace entries of the same name.
COPY env /etc/sandboxd/env
