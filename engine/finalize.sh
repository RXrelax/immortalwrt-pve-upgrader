#!/usr/bin/env bash
# Run in the Linux ImageBuilder tools container. Only a fully checked disk is published.
set -euo pipefail
umask 077
shopt -s nullglob
engine=$(cd -- "$(dirname -- "$0")" && pwd -P)
inputs=${INPUT_DIR:-/inputs}
output=${OUTPUT_DIR:-/out}
version=$(tr -d '\r\n' < "$inputs/version.txt")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid stable release" >&2; exit 1; }
images=("$output"/*-generic-ext4-combined.img.gz)
manifests=("$output"/*.manifest)
(( ${#images[@]} == 1 && ${#manifests[@]} == 1 )) || {
    echo "Expected one BIOS ext4 combined image and one build manifest." >&2; exit 1;
}
for name in router.qcow2 verification.json router.sha256; do
    [[ ! -e "$output/$name" && ! -L "$output/$name" ]] || { echo "Output already exists: $name" >&2; exit 1; }
done
stage=$(mktemp -d "$output/.finalize.XXXXXXXX")
scratch=$(mktemp -d)
trap 'rm -rf -- "$stage" "$scratch"' EXIT
fwtool=${FWTOOL:-}
if [[ -z "$fwtool" ]]; then
    if command -v fwtool >/dev/null; then
        fwtool=$(command -v fwtool)
    else
        # A resumed job may use a fresh container. Recover the tool from the
        # same verified ImageBuilder archive as the original build.
        # Some SDKs wrap this executable in a shell launcher expecting the
        # bundled loader, libraries, and a hidden sibling binary.
        tar -xf "$inputs/imagebuilder.tar.zst" -C "$scratch" --wildcards \
            '*/staging_dir/host/bin/*fwtool*' '*/staging_dir/host/lib/*'
        candidates=("$scratch"/*/staging_dir/host/bin/fwtool)
        (( ${#candidates[@]} == 1 )) || { echo "Missing ImageBuilder fwtool." >&2; exit 1; }
        fwtool=${candidates[0]}
    fi
fi
python3 -B "$engine/package_bios.py" "${images[0]}" "$stage/router.qcow2" \
    --version "$version" --manifest "${manifests[0]}" --adh-archive "$inputs/AdGuardHome.tar.gz" \
    --work-dir "$scratch" --fwtool "$fwtool" "$@" > "$stage/verification.json"
(cd "$stage" && sha256sum router.qcow2 > router.sha256)
mv -- "$stage/router.qcow2" "$stage/router.sha256" "$output/"
mv -- "$stage/verification.json" "$output/"
echo "QCOW2 geometry, filesystems, public binaries and content comparison passed."
