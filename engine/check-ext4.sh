#!/usr/bin/env bash
# Run only on the newly generated partition files, before assembling the disk.
set -euo pipefail
export LC_ALL=C
fs=$1
case "$fs" in
    /build/bios-*/build_dir/target-*/linux-x86_64/root.ext4|/build/bios-*/build_dir/target-*/linux-x86_64/tmp/*-ext4-combined.img.gz.kernel) ;;
    *) echo "Unexpected temporary filesystem path" >&2; exit 1 ;;
esac
test -f "$fs" && test ! -L "$fs"
if transcript=$(e2fsck -fn "$fs" 2>&1); then
    exit 0
else
    rc=$?
fi
printf '%s\n' "$transcript"
(( rc == 4 ))
# A different diagnostic calls for investigation before any automatic repair.
printf '%s\n' "$transcript" | awk '
    /^Padding at end of inode bitmap is not set\. Fix\? no$/ { padding++; next }
    /^e2fsck [0-9]/ || /^Pass [1-5]: Checking / || /^$/ { next }
    /^(rootfs|kernel): [*]+ WARNING: Filesystem still has errors [*]+$/ { next }
    /^(rootfs|kernel): [0-9]+\/[0-9]+ files \([^)]*\), [0-9]+\/[0-9]+ blocks$/ { next }
    { other++ }
    END { exit !(padding == 1 && !other) }
'
if e2fsck -fy "$fs"; then
    :
else
    rc=$?
    (( rc == 1 ))
fi
e2fsck -fn "$fs"
