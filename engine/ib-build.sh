#!/usr/bin/env bash
# Runs in a disposable Linux container: public release inputs only.
set -euo pipefail
export LC_ALL=C TZ=UTC FORCE_UNSAFE_CONFIGURE=1
engine=$(cd -- "$(dirname -- "$0")" && pwd)
fail() { echo "ImageBuilder: $*" >&2; exit 1; }
if (( $# )) && [[ $1 != --* ]]; then
    version=$1
    shift
else
    version=$(cat /inputs/version.txt)
fi
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Invalid stable version"
[[ $(uname -m) == x86_64 ]] || fail "An x86-64 Linux container is required."
for tool in tar zstd make python3 e2fsck; do command -v "$tool" >/dev/null || fail "Missing host tool: $tool"; done
mkdir -p /build /out
job=$(mktemp -d "/build/bios-${version}.XXXXXXXX")
cd "$job"
printf 'ImageBuilder work directory: %s\n' "$job"
tar --no-same-owner --strip-components=1 -xf /inputs/imagebuilder.tar.zst
grep -Fxq CONFIG_TARGET_x86_64=y .config || fail "Not an x86-64 ImageBuilder"
grep -Fxq CONFIG_SIGNATURE_CHECK=y .config || fail "Package signature checking unavailable"
grep -Fxq CONFIG_USE_APK=y .config || fail "This profile requires the supported APK release series"
manager=apk
python3 "$engine/ib-configure.py" "$version" "$manager" "$@"
python3 "$engine/ib-overlay.py" rootfs-overlay
pkgfile=/inputs/packages.txt
[[ -s $pkgfile ]] || pkgfile="$engine/templates/router-packages.txt"
packages=()
: > migration-packages.tsv
while IFS= read -r old || [[ -n $old ]]; do
    old=${old%$'\r'}
    [[ -n $old && $old != \#* ]] || continue
    [[ $old =~ ^[a-z0-9][a-z0-9.+-]*$ ]] || fail "Invalid requested package name"
    [[ $old != luci-app-adguardhome ]] || fail "Remove the obsolete luci-app-adguardhome; the native service is included."
    name=$old
    if [[ $old == opkg ]]; then name=apk-openssl; fi
    packages+=("$name")
    printf '%s\t%s\n' "$old" "$name" >> migration-packages.tsv
done < "$pkgfile"
(( ${#packages[@]} )) || fail "Empty public package baseline"
grep -Fxq $'luci-app-openclash\tluci-app-openclash' migration-packages.tsv || fail "Required OpenClash is missing from public package profile"

shopt -s nullglob
if [[ -e /inputs/extra || -L /inputs/extra ]]; then
    [[ -d /inputs/extra && ! -L /inputs/extra && -z "$(find /inputs/extra -mindepth 1 -print -quit)" ]] ||
        fail "Custom package overrides have no trusted digest. Use the official signed feeds."
fi
# Prepare a local snapshot only of official, signed package indexes and packages.
# The ImageBuilder itself still enforces signatures and exact dependency closure.
printf '%s\n' "${packages[@]}" > precache-packages.txt
python3 "$engine/precache-apk.py" precache-packages.txt
make -j1 image PROFILE=generic "BIN_DIR=$job/product" "FILES=$job/rootfs-overlay" "PACKAGES=${packages[*]}"

images=(product/*-generic-ext4-combined.img.gz)
manifests=(product/*.manifest)
roots=(build_dir/target-*/root-x86)
(( ${#images[@]} == 1 && ${#manifests[@]} == 1 && ${#roots[@]} == 1 )) || fail "Incomplete build product or ambiguous rootfs"
[[ ${images[0]##*/} == "immortalwrt-$version-x86-64-generic-ext4-combined.img.gz" ]] || fail "Image release/profile mismatch"
root=${roots[0]}
grep -Fxq "DISTRIB_RELEASE='$version'" "$root/etc/openwrt_release" || fail "Rootfs release mismatch"
[[ -x "$root/etc/init.d/openclash" && -x "$root/etc/init.d/AdGuardHome" && -L "$root/etc/rc.d/S95AdGuardHome" ]] || fail "Missing service/startup link"
cmp rootfs-overlay/usr/bin/AdGuardHome/AdGuardHome "$root/usr/bin/AdGuardHome/AdGuardHome"
# ImageBuilder writes the manifest from root.orig-x86. Check it against the
# installed database from the final image tree, after packages and overlays.
staging_dir/host/bin/apk --root "$job/$root" --no-network --arch x86_64 --repositories-file /dev/null \
    query --format json --fields name,version,provides,tags --installed '*' > installed.json
python3 "$engine/ib-verify-packages.py" "$version" "$manager" "${manifests[0]}"
for f in "${images[0]}" "${manifests[0]}" requested-packages.json; do
    [[ ! -e /out/${f##*/} && ! -L /out/${f##*/} ]] || fail "Output already exists: ${f##*/}"
done
ln -sfn "$job/staging_dir/host/bin/fwtool" /tmp/routerupgrade-fwtool
cp -- "${images[0]}" "${manifests[0]}" requested-packages.json /out/
printf 'Verified %s requested packages, both router services, and built %s.\n' "$(wc -l < migration-packages.tsv)" "${images[0]##*/}"
