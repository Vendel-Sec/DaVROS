#!/usr/bin/env bash
# Pack a lab container's filesystem into an ext4 image, to run binwalk on or to
# loop-mount.
#
#   demo/export-target-ext4.sh [container] [output]
#   (cd demo/evidence && binwalk -e davros-target.ext4)
#
# container  defaults to davros-target
# output     defaults to demo/evidence/<container>.ext4, overwritten if it exists
#
# Captures docker export, plus the volumes it leaves out (on davros-target,
# /keystore). mke2fs before 1.47.1 cannot read a tar stream, so the tree is
# unpacked and the image built in one fakeroot session, which keeps uids, gids,
# modes and device nodes as on the target without root here. The image is then
# shrunk to its minimum size.
#
# Needs docker, GNU tar, e2fsprogs and fakeroot:
#   sudo apt-get install e2fsprogs fakeroot
set -euo pipefail

CONTAINER="${1:-davros-target}"
DEMO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${2:-${DEMO}/evidence/${CONTAINER}.ext4}"

die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is not on PATH"
command -v fakeroot >/dev/null || die "fakeroot not found (sudo apt-get install fakeroot)"
# e2fsprogs lives in sbin, which a normal user's PATH may leave out.
PATH="$PATH:/usr/sbin:/sbin"
for tool in mkfs.ext4 e2fsck resize2fs; do
    command -v "$tool" >/dev/null || die "$tool not found (sudo apt-get install e2fsprogs)"
done
tar --version 2>/dev/null | grep -q "GNU tar" || die "GNU tar is required"
docker container inspect "$CONTAINER" >/dev/null 2>&1 || die "no container named $CONTAINER"
mkdir -p "$(dirname "$OUTPUT")"
# mkfs grows an existing file instead of replacing it, so start from nothing.
rm -f "$OUTPUT" "$OUTPUT.sha256"

work="$(mktemp -d)"
# The unpacked tree has read-only directories, which rm -rf cannot empty.
trap 'chmod -R u+rwX "$work" 2>/dev/null; rm -rf "$work"' EXIT

echo "== exporting the filesystem of $CONTAINER"
# A running container is copied as it is at this moment, not atomically.
docker export "$CONTAINER" -o "$work/rootfs.tar"

mapfile -t mounts < <(
    docker container inspect "$CONTAINER" \
        --format '{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' | sed '/^$/d; s|^/||'
)
if (( ${#mounts[@]} )); then
    echo "== adding volumes: ${mounts[*]/#//}"
    image="$(docker container inspect "$CONTAINER" --format '{{.Config.Image}}')"
    docker run --rm --volumes-from "$CONTAINER" --user 0 --network none \
        --entrypoint tar "$image" -C / --numeric-owner -cf - "${mounts[@]}" \
        > "$work/volumes.tar"
else
    tar -cf "$work/volumes.tar" --files-from /dev/null
fi

echo "== building $OUTPUT"
# Volumes are unpacked after the root filesystem, so each mount point takes the
# volume's own mode and owner (/keystore is 0750), not the empty directory's.
# The size is the tree plus a third and 64 MiB for metadata; resize2fs -M then
# trims it.
mkdir "$work/root"
fakeroot -- bash -euo pipefail -c '
    tar -xpf "$1/rootfs.tar" -C "$1/root" --numeric-owner
    tar -xpf "$1/volumes.tar" -C "$1/root" --numeric-owner
    kib=$(du -sk "$1/root" | cut -f1)
    inodes=$(find "$1/root" | wc -l)
    mkfs.ext4 -q -F -L "$2" -N $(( inodes * 5 / 4 + 1024 )) \
        -d "$1/root" "$3" "$(( kib * 4 / 3 + 65536 ))k" >/dev/null
' _ "$work" "${CONTAINER:0:16}" "$OUTPUT"
e2fsck -fp "$OUTPUT" >/dev/null
resize2fs -M "$OUTPUT" >/dev/null 2>&1
sha256sum "$OUTPUT" > "$OUTPUT.sha256"

echo
echo "$(du -h "$OUTPUT" | cut -f1)  $OUTPUT"
