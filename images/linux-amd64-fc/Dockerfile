# Root filesystem of the Firecracker review guest (linux/amd64). build.sh
# exports this image into a read-only ext4 file; it never runs as a container.
# Same guest contract as images/linux-arm64 (review-arm64): the tools of its
# golang:bookworm base (git, openssh-client, procps, wget, curl), plus
# bash, a C toolchain and python3, user 1000:1000 with home /home/user.
#
# Two targets: `review` (review-amd64, no Go) and `review-go126`
# (review-go126-amd64: review plus the Go toolchain of the Mac's
# images/linux-arm64 and a module cache of the repositories in GOMOD_REPOS).
ARG GO_IMAGE=golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b

FROM --platform=linux/amd64 debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS review

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

# Build-time only: pre-download the module graphs of the repositories whose
# reviews run on this image, as images/linux-arm64 does. Each entry is
# <clone URL>@<full commit>; rebuild with new commits whenever a listed
# repository changes go.mod/go.sum. The cache is the guest's first module
# proxy (GOPROXY=file://...); anything else comes from proxy.golang.org.
FROM --platform=linux/amd64 ${GO_IMAGE} AS modcache
ARG GOMOD_REPOS="\
https://github.com/gitmoot/gitmoot@8d58db9dcc5846b90af4efcb5757cee63e3265f9"
ENV GOTOOLCHAIN=local GOMODCACHE=/opt/gomodcache GOCACHE=/tmp/go-build
RUN set -eu; \
    for entry in $GOMOD_REPOS; do \
        url="${entry%@*}"; commit="${entry##*@}"; src=/tmp/src; \
        rm -rf "$src"; git init -q "$src"; \
        git -C "$src" fetch -q --depth 1 "$url" "$commit"; \
        git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD; \
        test "$(git -C "$src" rev-parse HEAD)" = "$commit"; \
        if [ -f "$src/go.work" ]; then \
            (cd "$src" && go mod download all && go list -deps -test ./... >/dev/null); \
        fi; \
        for mod in $(cd "$src" && find . -name go.mod -not -path '*/vendor/*' -not -path '*/testdata/*'); do \
            dir="$src/$(dirname "$mod")"; \
            (cd "$dir" && GOWORK=off go mod download all \
                && GOWORK=off go list -deps -test ./... >/dev/null \
                && GOWORK=off GOPROXY=off go mod verify \
                && GOWORK=off GOPROXY=off go list -deps -test ./... >/dev/null); \
        done; \
    done; \
    rm -rf /tmp/src /tmp/go-build /opt/gomodcache/cache/vcs

FROM review AS review-go126
# The Go distribution of GO_IMAGE, unchanged (root-owned, read-only image).
COPY --from=modcache /usr/local/go /usr/local/go
# Only the module proxy layout (cache/download: .info, .mod, .zip, .ziphash)
# is kept; the guest extracts what a build needs into its own GOMODCACHE.
COPY --from=modcache /opt/gomodcache/cache/download /opt/gomodcache/cache/download

# Login shells reset PATH (/etc/profile); go and gofmt stay on it.
RUN ln -s /usr/local/go/bin/go /usr/local/go/bin/gofmt /usr/local/bin/
