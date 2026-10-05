# E2B base image for the Apple container driver (linux/arm64), the image of
# profile=e2b templates on the Mac. Upstream E2B envd (Apache-2.0, see
# /usr/share/doc/envd) is the entrypoint. Same guest contract as
# images/e2b-amd64-fc: E2B base tools, user 1000:1000 with home /home/user
# and passwordless sudo. No compilers.
# Build (on the Mac, from a checkout of this repository):
#   container build --platform linux/arm64 --tag sandboxd/e2b-arm64:<version> images/e2b-arm64
ARG BASE_IMAGE=debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

# Build-time only: fetch the envd 0.9.0 release binary from E2B's public
# bucket and the license at the release commit (e2b-dev/infra 0c2108b1,
# "chore(main): release envd 0.9.0"; the release has no git tag). Both are
# SHA-256 pinned; the build fails on any mismatch. Runs on the build
# platform: the binary is only downloaded here, never executed.
FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS envd
RUN set -eu; \
    version=0.9.0; \
    commit=0c2108b1b76a66d18cf095d51fd7c51c703648ae; \
    url="https://storage.googleapis.com/e2b-artifact-binaries/envd/v$version/arm64/envd"; \
    sum=bf3469762eebf3d4880edcd8c36c7768a53b455a65f4eb2db96abd99d5d89189; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    mkdir /out; \
    curl -fsSL --proto '=https' -o /out/envd "$url"; \
    echo "$sum  /out/envd" | sha256sum -c -; \
    curl -fsSL --proto '=https' -o /out/LICENSE \
        "https://raw.githubusercontent.com/e2b-dev/infra/$commit/LICENSE"; \
    echo "b4ef1bf811cb4095229fb86b574199e467c78f0ac4078cf8be62189e1fbd0818  /out/LICENSE" | sha256sum -c -; \
    printf '%s\n' \
        "E2B envd $version, Copyright 2023 FoundryLabs, Inc., Apache License 2.0 (see LICENSE)." \
        "Source: https://github.com/e2b-dev/infra/tree/$commit/packages/envd" \
        "Binary: $url" \
        "SHA-256: $sum" >/out/SOURCE; \
    chmod 0755 /out/envd; \
    chmod 0644 /out/LICENSE /out/SOURCE

FROM --platform=linux/arm64 ${BASE_IMAGE}

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
    && mkdir -p /etc/sandboxd \
    && printf '%s\n' PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/home/user USER=user LANG=C.UTF-8 TMPDIR=/tmp >/etc/sandboxd/env

COPY --from=envd /out/envd /usr/bin/envd
COPY --from=envd /out/LICENSE /out/SOURCE /usr/share/doc/envd/

USER root
WORKDIR /home/user
ENTRYPOINT ["/usr/bin/envd", "-isnotfc", "-no-cgroups"]
