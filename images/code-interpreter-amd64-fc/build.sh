#!/bin/sh
# Builds the read-only Firecracker root filesystem of the E2B code-interpreter
# template, code-interpreter-v1 (docs/firecracker.md, "Code-interpreter
# image"): upstream e2b-dev/code-interpreter template/ plus the e2b guest
# contract of images/e2b-amd64-fc.
# Usage (root, from the repository root):
#   images/code-interpreter-amd64-fc/build.sh [/var/lib/sandboxd-fc]
# SANDBOXD_GUEST_AGENT=<file>: use this sandboxd-guest-agent (from the
# linux-amd64 release tarball of the same tag) instead of building it with Go.
# Output: <dir>/images/code-interpreter-amd64-<sha256 prefix>.ext4 (0444,
# root-owned) plus a .sha256 file. The docker image, its containers and the
# build-cache entries this build created are removed.
set -eu

# Upstream template: e2b-dev/code-interpreter tag
# @e2b/code-interpreter-template@0.4.6 (Apache-2.0), fetched as GitHub's
# archive of the tagged commit and checked against its SHA-256.
ci_tag=@e2b/code-interpreter-template@0.4.6
ci_commit=8d51873ccf620498347210dc3ec9698cf67c2829
ci_url=https://codeload.github.com/e2b-dev/code-interpreter/tar.gz/$ci_commit
ci_sha256=0a03c6b0ccc08183934af0c786ee751e9d1d15a7e7ec88fd2d0c8a496eb130ca

# Upstream E2B envd 0.9.0 (Apache-2.0), the binary of images/e2b-amd64-fc:
# release binary from E2B's public bucket, built from e2b-dev/infra commit
# 0c2108b1 ("chore(main): release envd 0.9.0"; the release has no git tag).
envd_version=0.9.0
envd_commit=0c2108b1b76a66d18cf095d51fd7c51c703648ae
envd_url=https://storage.googleapis.com/e2b-artifact-binaries/envd/v$envd_version/envd
envd_sha256=c42a31d738718b5cf7654e258e5b111308646a905331b266294cdcbeb0a02355
license_url=https://raw.githubusercontent.com/e2b-dev/infra/$envd_commit/LICENSE
license_sha256=b4ef1bf811cb4095229fb86b574199e467c78f0ac4078cf8be62189e1fbd0818

out=${1:-/var/lib/sandboxd-fc}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tag=sbx-fc-code-interpreter-rootfs:build
work=$(mktemp -d /var/tmp/sbx-fc-code-interpreter-rootfs.XXXXXX)
cid=

# Build-cache entries of this Dockerfile: every RUN carries the SBX_IMAGE
# marker, every COPY reads from sbx-ci/.
cache_ids() {
    docker buildx du --verbose 2>/dev/null | awk '/^ID:/{id=$2}
        /^Description:/ && (/SBX_IMAGE=code-interpreter-amd64-fc/ || / COPY (--chmod=[0-7]+ )?sbx-ci\// ||
            / WORKDIR \/root$/ || /pulled from docker\.io\/library\/python:3\.13@sha256:138ea0589fbe/ ||
            /local source for (context|dockerfile)/){print id}' | sort
}
cleanup() {
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1 || true
    docker rmi -f "$tag" >/dev/null 2>&1 || true
    # Drop only the build-cache entries this build created; entries that
    # existed before it (other users' builds) are left alone. Children go
    # before their parents, so repeat while entries go away (one pass per
    # layer).
    if [ -f "$work/cache.before" ]; then
        left=
        while :; do
            ids=$(cache_ids | comm -13 "$work/cache.before" -)
            [ -n "$ids" ] && [ "$ids" != "$left" ] || break
            left=$ids
            for id in $ids; do
                docker buildx prune -f --filter "id=$id" >/dev/null 2>&1 || true
            done
        done
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

ctx=$work/ctx/sbx-ci
mkdir -p "$ctx/doc/code-interpreter" "$ctx/doc/envd" "$work/root"
cache_ids >"$work/cache.before"
cp "$here/Dockerfile" "$work/ctx/Dockerfile"
cp "$here/sandboxd-start.sh" "$ctx/sandboxd-start.sh"

curl -fsSL --proto '=https' -o "$work/code-interpreter.tar.gz" "$ci_url"
printf '%s  %s\n' "$ci_sha256" "$work/code-interpreter.tar.gz" | sha256sum -c --quiet -
tar -C "$ctx" --no-same-owner --strip-components=1 -xzf "$work/code-interpreter.tar.gz" \
    "code-interpreter-$ci_commit/template" "code-interpreter-$ci_commit/LICENSE"
mv "$ctx/LICENSE" "$ctx/doc/code-interpreter/LICENSE"
cat >"$ctx/doc/code-interpreter/SOURCE" <<EOF
E2B code-interpreter template $ci_tag, Copyright FoundryLabs, Inc., Apache License 2.0 (see LICENSE).
Source: https://github.com/e2b-dev/code-interpreter/tree/$ci_commit/template
Archive: $ci_url
SHA-256: $ci_sha256
Installed: /root/.server (server/), /root/requirements.txt, /root/.jupyter,
/root/.ipython/profile_default, /root/.config/matplotlib/.matplotlibrc.
Changes: requirements.txt pins e2b_charts==1.0.0 (upstream: unpinned); the
systemd units (systemd/jupyter.service, systemd/code-interpreter.service) are
replaced by /root/.jupyter/sandboxd-start.sh (sandboxd, gitmoot/sandboxd).
EOF

if [ -n "${SANDBOXD_GUEST_AGENT:-}" ]; then
    install -m 0755 "$SANDBOXD_GUEST_AGENT" "$ctx/sandboxd-guest-agent"
else
    (cd "$repo" && env GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.4}" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags=-s -o "$ctx/sandboxd-guest-agent" ./cmd/sandboxd-guest-agent)
fi
curl -fsSL --proto '=https' -o "$ctx/envd" "$envd_url"
printf '%s  %s\n' "$envd_sha256" "$ctx/envd" | sha256sum -c --quiet -
curl -fsSL --proto '=https' -o "$ctx/doc/envd/LICENSE" "$license_url"
printf '%s  %s\n' "$license_sha256" "$ctx/doc/envd/LICENSE" | sha256sum -c --quiet -
cat >"$ctx/doc/envd/SOURCE" <<EOF
E2B envd $envd_version, Copyright 2023 FoundryLabs, Inc., Apache License 2.0 (see LICENSE).
Source: https://github.com/e2b-dev/infra/tree/$envd_commit/packages/envd
Binary: $envd_url
SHA-256: $envd_sha256
EOF
# The template's environment (template.py set_envs) on top of the e2b one.
cat >"$ctx/env" <<'EOF'
PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/home/user
USER=user
LANG=C.UTF-8
TMPDIR=/tmp
PIP_DEFAULT_TIMEOUT=100
PIP_DISABLE_PIP_VERSION_CHECK=1
PIP_NO_CACHE_DIR=1
JAVA_VERSION=11
JAVA_HOME=/usr/lib/jvm/jdk-11
IJAVA_VERSION=1.3.0
R_VERSION=4.5.*
EOF
# Modes do not depend on the archive or the umask: COPY keeps them.
chmod -R u=rwX,go=rX "$work/ctx"
chmod 0755 "$ctx/envd" "$ctx/sandboxd-guest-agent" "$ctx/sandboxd-start.sh" \
    "$ctx/template/jupyter-healthcheck.sh"

docker build --pull --platform linux/amd64 -t "$tag" "$work/ctx"
cid=$(docker create --platform linux/amd64 "$tag" /sbin/sandboxd-agent)
docker export "$cid" | tar -C "$work/root" --numeric-owner -xpf -
docker rm -f "$cid" >/dev/null
cid=

# Docker replaces these at run time; the guest needs its own. The guest
# resolves names through public resolvers reached over its NAT path; the
# host resolver (127.0.0.53) is deliberately unreachable.
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions edns0\n' >"$work/root/etc/resolv.conf"
printf '127.0.0.1\tlocalhost\n127.0.1.1\tsandbox\n' >"$work/root/etc/hosts"
printf 'sandbox\n' >"$work/root/etc/hostname"
rm -f "$work/root/.dockerenv"
for dir in proc sys dev run tmp var/tmp var/log home/user root/.server/.venv; do
    test -d "$work/root/$dir"
done
chmod 0644 "$work/root/etc/sandboxd/env"
chmod 0755 "$work/root/sbin/sandboxd-agent" "$work/root/usr/bin/envd" \
    "$work/root/root/.jupyter/sandboxd-start.sh"
chmod 0440 "$work/root/etc/sudoers.d/user"
test "$(stat -c '%u:%g %a' "$work/root/home/user")" = "1000:1000 755"
test "$(stat -c '%u:%g %a' "$work/root/root/.jupyter/sandboxd-start.sh")" = "0:0 755"
# The guest agent formats the writable root disk with it.
test -x "$work/root/sbin/mkfs.ext4"

# Size: allocated blocks plus 5% and 64 MiB, inodes for every file plus
# 10%; no journal and no reserved blocks (mounted read-only). Small files
# dominate this tree, so the allocated size, not the apparent one, is the
# floor.
kib=$(du -sk "$work/root" | cut -f1)
files=$(find "$work/root" -xdev | wc -l)
size=$(( kib * 105 / 100 / 1024 + 64 ))
image="$work/rootfs.ext4"
truncate -s "${size}M" "$image"
mkfs.ext4 -q -F -L sbxroot -O ^has_journal -m 0 -N $(( files * 11 / 10 )) -E root_owner=0:0 \
    -d "$work/root" "$image"
rm -rf "$work/root"
sum=$(sha256sum "$image" | cut -c1-64)
mkdir -p "$out/images"
dest="$out/images/code-interpreter-amd64-$(printf %s "$sum" | cut -c1-12).ext4"
chown root:root "$image"
chmod 0444 "$image"
mv -f "$image" "$dest"
printf '%s  %s\n' "$sum" "$(basename "$dest")" >"$dest.sha256"
chmod 0444 "$dest.sha256"
echo "$dest"
