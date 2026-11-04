#!/bin/sh
# Installs the pinned Firecracker, jailer and guest kernel (docs/firecracker.md).
# Usage (root): images/linux-amd64-fc/install-firecracker.sh [--kernel 6.18.51] [/var/lib/sandboxd-fc]
# Every download is checked against the SHA-256 pinned here before use.
# --kernel selects another pinned guest kernel from the same Firecracker CI set;
# the default stays 6.1.186. 6.18.51 (Landlock ABI 7) is a Firecracker-supported
# guest kernel since v1.16.1. Both kernels can be installed side by side; each
# instance picks its own with -fc-kernel.
set -eu

kernel_version=6.1.186
if [ "${1:-}" = --kernel ]; then
    [ $# -ge 2 ] || { echo "usage: $0 [--kernel 6.1.186|6.18.51] [dir]" >&2; exit 2; }
    kernel_version=$2
    shift 2
fi
out=${1:-/var/lib/sandboxd-fc}
fc_version=v1.17.0
fc_sha256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
fc_url=https://github.com/firecracker-microvm/firecracker/releases/download/$fc_version/firecracker-$fc_version-x86_64.tgz
# Firecracker CI's guest kernels for the v1.17 release line (with virtio-vsock,
# devtmpfs and IP autoconfiguration built in).
case $kernel_version in
6.1.186) kernel_sha256=ea0e55d03dbaebc79a58644308e0517b7a33f1530a84848d9edf47ffa61f69c8 ;;
6.18.51) kernel_sha256=0545ba1781fc06cfa1d7699069057f4538103fd1644100cf0da434899a1ed447 ;;
*) echo "unsupported kernel $kernel_version (pinned: 6.1.186, 6.18.51)" >&2; exit 2 ;;
esac
kernel_url=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260930-a738f18a8db0-0/x86_64/vmlinux-$kernel_version

work=$(mktemp -d /var/tmp/sbx-fc-install.XXXXXX)
trap 'rm -rf "$work"' EXIT INT TERM

fetch() { # url sha256 dest
    curl -fsSL --proto '=https' -o "$3" "$1"
    printf '%s  %s\n' "$2" "$3" | sha256sum -c --quiet -
}

fetch "$fc_url" "$fc_sha256" "$work/fc.tgz"
fetch "$kernel_url" "$kernel_sha256" "$work/vmlinux"
tar -C "$work" -xzf "$work/fc.tgz"
release="$work/release-$fc_version-x86_64"

install -d -m 0755 -o root -g root "$out" "$out/bin" "$out/kernel" "$out/images"
install -m 0755 -o root -g root "$release/firecracker-$fc_version-x86_64" "$out/bin/firecracker"
install -m 0755 -o root -g root "$release/jailer-$fc_version-x86_64" "$out/bin/jailer"
install -m 0444 -o root -g root "$work/vmlinux" "$out/kernel/vmlinux-$kernel_version"
"$out/bin/firecracker" --version | head -1
"$out/bin/jailer" --version | head -1
echo "$out/kernel/vmlinux-$kernel_version"
