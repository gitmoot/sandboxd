# Root filesystem of the Firecracker E2B guest (linux/amd64), the image of
# profile=e2b templates. build.sh exports this image into a read-only ext4
# file; it never runs as a container. The guest agent is PID 1; with the
# kernel argument sandboxd.envd=1 it starts upstream E2B envd
# (/usr/bin/envd, Apache-2.0, see /usr/share/doc/envd). Same guest contract
# as images/e2b-arm64: E2B base tools, user 1000:1000 with home /home/user
# and passwordless sudo. No compilers.
FROM --platform=linux/amd64 debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl e2fsprogs git gzip iproute2 netbase procps \
    python3 python-is-python3 sudo tar \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 user \
    && useradd --uid 1000 --gid 1000 --home /home/user --create-home --shell /bin/bash user \
    && chmod 0755 /home/user \
    && usermod --shell /bin/bash root \
    && printf 'user ALL=(ALL:ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/user \
    && chmod 0440 /etc/sudoers.d/user \
    && mkdir -p /etc/sandboxd /usr/share/doc/envd

# PID 1: mounts the guest filesystems, sets up the writable root and starts
# envd (cmd/sandboxd-guest-agent).
COPY sandboxd-guest-agent /sbin/sandboxd-agent

# E2B envd 0.9.0 release binary; build.sh verifies its SHA-256.
COPY envd /usr/bin/envd
COPY LICENSE SOURCE /usr/share/doc/envd/

# The image environment, applied to every guest command (Dockerfile ENV is
# lost by the export). Request variables replace entries of the same name.
COPY env /etc/sandboxd/env
