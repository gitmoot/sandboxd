#!/bin/sh
# Builds the read-only Firecracker E2B guest root filesystem, the image of
# profile=e2b templates (docs/firecracker.md, "E2B base image").
# Usage (root, from the repository root):
#   images/e2b-amd64-fc/build.sh [/var/lib/sandboxd-fc]
# SANDBOXD_GUEST_AGENT=<file>: use this sandboxd-guest-agent (from the
# linux-amd64 release tarball of the same tag) instead of building it with Go.
# Output: <dir>/images/e2b-amd64-<sha256 prefix>.ext4 (0444, root-owned)
# plus a .sha256 file. The docker image and containers it creates are removed.
set -eu

# Upstream E2B envd 0.9.0 (Apache-2.0): release binary from E2B's public
# bucket, built from e2b-dev/infra commit 0c2108b1 ("chore(main): release
# envd 0.9.0"; the release has no git tag).
envd_version=0.9.0
envd_commit=0c2108b1b76a66d18cf095d51fd7c51c703648ae
envd_url=https://storage.googleapis.com/e2b-artifact-binaries/envd/v$envd_version/envd
envd_sha256=c42a31d738718b5cf7654e258e5b111308646a905331b266294cdcbeb0a02355
license_url=https://raw.githubusercontent.com/e2b-dev/infra/$envd_commit/LICENSE
license_sha256=b4ef1bf811cb4095229fb86b574199e467c78f0ac4078cf8be62189e1fbd0818

out=${1:-/var/lib/sandboxd-fc}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tag=sbx-fc-e2b-rootfs:build
work=$(mktemp -d /var/tmp/sbx-fc-e2b-rootfs.XXXXXX)
cid=
cache_ids() {
    docker buildx du --verbose 2>/dev/null | awk '/^ID:/{id=$2}
        /^Description:/ && (/python3 python-is-python3 sudo tar/ || /COPY envd \/usr\/bin\/envd/ ||
            /COPY LICENSE SOURCE \/usr\/share\/doc\/envd/ || /COPY sandboxd-guest-agent \/sbin\/sandboxd-agent/ ||
            /COPY env \/etc\/sandboxd\/env/ || /local source for (context|dockerfile)/){print id}' | sort
}
cleanup() {
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
    docker rmi -f "$tag" >/dev/null 2>&1 || true
    # Drop only the build-cache entries this build created; entries that
    # existed before it (other users' builds) are left alone. Children go
    # before their parents, so repeat until none is left (one pass per layer).
    if [ -f "$work/cache.before" ]; then
        for pass in 1 2 3 4 5 6 7 8; do
            ids=$(cache_ids | comm -13 "$work/cache.before" -)
            [ -n "$ids" ] || break
            for id in $ids; do
                docker buildx prune -f --filter "id=$id" >/dev/null 2>&1 || true
            done
        done
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mkdir -p "$work/ctx" "$work/root"
cache_ids >"$work/cache.before"
cp "$here/Dockerfile" "$work/ctx/Dockerfile"
if [ -n "${SANDBOXD_GUEST_AGENT:-}" ]; then
    install -m 0755 "$SANDBOXD_GUEST_AGENT" "$work/ctx/sandboxd-guest-agent"
else
    (cd "$repo" && env GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags=-s -o "$work/ctx/sandboxd-guest-agent" ./cmd/sandboxd-guest-agent)
fi
curl -fsSL --proto '=https' -o "$work/ctx/envd" "$envd_url"
printf '%s  %s\n' "$envd_sha256" "$work/ctx/envd" | sha256sum -c --quiet -
curl -fsSL --proto '=https' -o "$work/ctx/LICENSE" "$license_url"
printf '%s  %s\n' "$license_sha256" "$work/ctx/LICENSE" | sha256sum -c --quiet -
chmod 0755 "$work/ctx/envd"
chmod 0644 "$work/ctx/LICENSE"
cat >"$work/ctx/SOURCE" <<EOF
E2B envd $envd_version, Copyright 2023 FoundryLabs, Inc., Apache License 2.0 (see LICENSE).
Source: https://github.com/e2b-dev/infra/tree/$envd_commit/packages/envd
Binary: $envd_url
SHA-256: $envd_sha256
EOF
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
chmod 0755 "$work/root/sbin/sandboxd-agent" "$work/root/usr/bin/envd"
chmod 0440 "$work/root/etc/sudoers.d/user"
test "$(stat -c '%u:%g %a' "$work/root/home/user")" = "1000:1000 755"

# Size: content plus 25% headroom; no journal (mounted read-only).
kib=$(du -sk --apparent-size "$work/root" | cut -f1)
size=$(( (kib * 5 / 4 / 1024 + 64) ))
image="$work/rootfs.ext4"
truncate -s "${size}M" "$image"
mkfs.ext4 -q -F -L sbxroot -O ^has_journal -E root_owner=0:0 -d "$work/root" "$image"
sum=$(sha256sum "$image" | cut -c1-64)
mkdir -p "$out/images"
dest="$out/images/e2b-amd64-$(printf %s "$sum" | cut -c1-12).ext4"
install -m 0444 -o root -g root "$image" "$dest"
printf '%s  %s\n' "$sum" "$(basename "$dest")" >"$dest.sha256"
chmod 0444 "$dest.sha256"
echo "$dest"
