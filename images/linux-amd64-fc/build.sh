#!/bin/sh
# Builds the read-only Firecracker guest root filesystem (docs/firecracker.md).
# Usage (root, from the repository root):
#   images/linux-amd64-fc/build.sh [/var/lib/sandboxd-fc]
# Output: <dir>/images/review-amd64-<sha256 prefix>.ext4 (0444, root-owned)
# plus a .sha256 file. The docker image and containers it creates are removed.
set -eu

out=${1:-/var/lib/sandboxd-fc}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tag=sbx-fc-rootfs:build
work=$(mktemp -d /var/tmp/sbx-fc-rootfs.XXXXXX)
cid=
cleanup() {
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
    docker rmi -f "$tag" >/dev/null 2>&1 || true
    # Drop only this Dockerfile's build cache (about 520 MB); other users'
    # cache entries are left alone.
    for id in $(docker buildx du --verbose 2>/dev/null | awk '/^ID:/{id=$2}
        /^Description:/ && (/e2fsprogs git make gcc/ || /COPY sandboxd-guest-agent \/sbin\/sandboxd-agent/ || /COPY env \/etc\/sandboxd\/env/){print id}'); do
        docker buildx prune -f --filter "id=$id" >/dev/null 2>&1 || true
    done
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/ctx" "$work/root"
cp "$here/Dockerfile" "$work/ctx/Dockerfile"
(cd "$repo" && env GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags=-s -o "$work/ctx/sandboxd-guest-agent" ./cmd/sandboxd-guest-agent)
cat >"$work/ctx/env" <<'EOF'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/user
USER=user
LANG=C.UTF-8
TMPDIR=/tmp
EOF

docker build --pull --platform linux/amd64 -t "$tag" "$work/ctx"
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
dest="$out/images/review-amd64-$(printf %s "$sum" | cut -c1-12).ext4"
install -m 0444 -o root -g root "$image" "$dest"
printf '%s  %s\n' "$sum" "$(basename "$dest")" >"$dest.sha256"
chmod 0444 "$dest.sha256"
echo "$dest"
