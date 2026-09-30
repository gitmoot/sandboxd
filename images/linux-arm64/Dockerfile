# Build for linux/arm64 from the resolved immutable image index.
ARG GO_IMAGE=golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b

# Build-time only: pre-download the module graphs of the repositories whose
# reviews run on this image. Guests have no network egress, so this cache is
# the only module source they see. Each entry is <clone URL>@<full commit>;
# rebuild with new commits whenever a listed repository changes go.mod/go.sum
# (see docs/compatibility.md, "Review image module cache").
FROM --platform=linux/arm64 ${GO_IMAGE} AS modcache
ARG GOMOD_REPOS="\
https://github.com/gitmoot/gitmoot@5a26c9885de65600c590c846b37d3ec0bd91aeae \
https://github.com/gitmoot/sandboxd@10f80de955e3c3a4a350c01e35c70595d676d6cf"
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
    rm -rf /tmp/src /tmp/go-build

FROM --platform=linux/arm64 ${GO_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git make gcc g++ python3 tar gzip unzip \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 user \
    && useradd --uid 1000 --gid 1000 --home /home/user --create-home --shell /bin/sh user

# Root-owned and read-only to the guest user (Go writes the cache 0444/0555).
COPY --from=modcache /opt/gomodcache /opt/gomodcache

# The provider mounts a private 10 GiB ext4 volume over /home/user; the
# image itself contains no GitHub or model credential material. Modules come
# only from /opt/gomodcache and are still checked against each repo's go.sum.
ENV HOME=/home/user GOTOOLCHAIN=local GOPATH=/home/user/go \
    GOCACHE=/home/user/.cache/go-build TMPDIR=/tmp \
    GOMODCACHE=/opt/gomodcache GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
WORKDIR /home/user
USER 1000:1000
CMD ["/bin/sleep", "2147483647"]
