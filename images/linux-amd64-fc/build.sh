#!/bin/sh
# Builds the read-only Firecracker guest root filesystem (docs/firecracker.md).
# Usage (root, from the repository root):
#   images/linux-amd64-fc/build.sh [--go126] [/var/lib/sandboxd-fc]
# SANDBOXD_GUEST_AGENT=<file>: use this sandboxd-guest-agent (from the
# linux-amd64 release tarball of the same tag) instead of building it with Go.
# Output: <dir>/images/review-amd64-<sha256 prefix>.ext4, or with --go126
# <dir>/images/review-go126-amd64-<sha256 prefix>.ext4 (0444, root-owned)
# plus a .sha256 file. The docker image and containers it creates are removed.
set -eu

target=review
name=review-amd64
go126=0
if [ "${1:-}" = "--go126" ]; then
    target=review-go126
    name=review-go126-amd64
    go126=1
    shift
fi
out=${1:-/var/lib/sandboxd-fc}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tag=sbx-fc-rootfs:build-$target-$$
work=$(mktemp -d /var/tmp/sbx-fc-rootfs.XXXXXX)
cid=
cleanup() {
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
    docker rmi -f "$tag" >/dev/null 2>&1 || true
    # Drop only this Dockerfile's build cache (about 520 MB, more with
    # --go126); other users' cache entries are left alone. A
    # record is prunable only once its children are gone, so repeat until
    # nothing matches. The golang base image's pulled layers (about 0.7 GB)
    # are tried too, but BuildKit may keep them while it shares their
    # snapshots with other cache records; `docker buildx du` lists them.
    pass=0
    while [ "$pass" -lt 6 ]; do
        ids=$(docker buildx du --verbose 2>/dev/null | awk -v go126="$go126" '/^ID:/{id=$2}
            /^Description:/ && (/e2fsprogs git make gcc/ || /COPY sandboxd-guest-agent \/sbin\/sandboxd-agent/ || /COPY env \/etc\/sandboxd\/env/ ||
                /GOMOD_REPOS/ || /COPY --from=modcache/ || /ln -s \/usr\/local\/go\/bin\/go/ ||
                (go126 && /pulled from docker.io\/library\/golang:1.26.4-bookworm@/)){print id}')
        [ -n "$ids" ] || break
        for id in $ids; do
            docker buildx prune -f --filter "id=$id" >/dev/null 2>&1 || true
        done
        pass=$((pass + 1))
    done
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/ctx" "$work/root"
cp "$here/Dockerfile" "$work/ctx/Dockerfile"
if [ -n "${SANDBOXD_GUEST_AGENT:-}" ]; then
    install -m 0755 "$SANDBOXD_GUEST_AGENT" "$work/ctx/sandboxd-guest-agent"
else
    (cd "$repo" && env GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags=-s -o "$work/ctx/sandboxd-guest-agent" ./cmd/sandboxd-guest-agent)
fi
if [ "$target" = review ]; then
    cat >"$work/ctx/env" <<'EOF'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/user
USER=user
LANG=C.UTF-8
TMPDIR=/tmp
EOF
else
    # The Mac's review-go126 environment, except that modules missing from
    # the image's cache come from proxy.golang.org: the cache is the first
    # proxy, and GOMODCACHE is on the guest's private writable home disk.
    cat >"$work/ctx/env" <<'EOF'
PATH=/home/user/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/user
USER=user
LANG=C.UTF-8
TMPDIR=/tmp
GOTOOLCHAIN=local
GOPATH=/home/user/go
GOCACHE=/home/user/.cache/go-build
GOMODCACHE=/home/user/go/pkg/mod
GOPROXY=file:///opt/gomodcache/cache/download,https://proxy.golang.org,direct
GOFLAGS=-mod=readonly
EOF
fi

docker build --pull --platform linux/amd64 --target "$target" -t "$tag" "$work/ctx"
cid=$(docker create --platform linux/amd64 "$tag" /sbin/sandboxd-agent)
docker export "$cid" | tar -C "$work/root" --numeric-owner -xpf -

# Docker replaces these at run time; the guest needs its own. The guest
# resolves names through public resolvers reached over its NAT path; the
# host resolver (127.0.0.53) is deliberately unreachable.
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions edns0\n' >"$work/root/etc/resolv.conf"
printf '127.0.0.1\tlocalhost\n127.0.1.1\tsandbox\n' >"$work/root/etc/hosts"
printf 'sandbox\n' >"$work/root/etc/hostname"
rm -f "$work/root/.dockerenv"
for dir in proc sys dev run tmp var/tmp home/user; do
    test -d "$work/root/$dir"
done
chmod 0644 "$work/root/etc/sandboxd/env"
chmod 0755 "$work/root/sbin/sandboxd-agent"

# Size: content plus 25% headroom; no journal (mounted read-only).
kib=$(du -sk --apparent-size "$work/root" | cut -f1)
size=$(( (kib * 5 / 4 / 1024 + 64) ))
image="$work/rootfs.ext4"
truncate -s "${size}M" "$image"
mkfs.ext4 -q -F -L sbxroot -O ^has_journal -E root_owner=0:0 -d "$work/root" "$image"
sum=$(sha256sum "$image" | cut -c1-64)
mkdir -p "$out/images"
dest="$out/images/$name-$(printf %s "$sum" | cut -c1-12).ext4"
install -m 0444 -o root -g root "$image" "$dest"
printf '%s  %s\n' "$sum" "$(basename "$dest")" >"$dest.sha256"
chmod 0444 "$dest.sha256"
echo "$dest"
