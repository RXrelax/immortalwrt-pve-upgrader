"""Create a raw, tar-formatted virtual disk for an offline router restore."""

import hashlib
import io
import os
import re
import tarfile

from .layout import DEFAULT_LAYOUT, Layout


_RUN_SCRIPT = rb"""#!/bin/sh
umask 077
export LC_ALL=C

fail() { printf 'Restore stopped: %s\n' "$1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Root access is required.'
grep -Fqx "DISTRIB_ID='ImmortalWrt'" /etc/openwrt_release 2>/dev/null &&
    grep -Fqx "DISTRIB_RELEASE='@VERSION@'" /etc/openwrt_release 2>/dev/null ||
    fail 'This carrier requires ImmortalWrt @VERSION@.'
[ ! -d /sys/firmware/efi ] || fail 'Expected a legacy BIOS boot.'
[ -x /sbin/sysupgrade ] || fail 'The target has no sysupgrade restore utility.'
command -v apk >/dev/null || command -v opkg >/dev/null || fail 'Package manager unavailable.'
ubus -t 5 wait_for network.interface >/dev/null 2>&1 && [ ! -e /tmp/.config_pending ] ||
    fail 'First-boot network defaults are not ready. Wait a minute and retry before changing any disk.'
for nic in /sys/class/net/*; do
    [ -e "$nic/device" ] || continue
    [ "$(cat "$nic/carrier" 2>/dev/null)" != 1 ] ||
        fail 'A guest NIC has a live link. Disconnect the router NICs in PVE before restoring.'
done

rootdev=$(awk '$5=="/" && $6 ~ /(^|,)rw(,|$)/ {
    for (i=7; i<NF; i++) if ($i=="-" && $(i+1)=="ext4") print $3
}' /proc/self/mountinfo)
rootpart=$(readlink -f "/sys/dev/block/$rootdev") || fail 'Cannot identify writable ext4 root.'
base=${rootpart%/*}
rootbase=${base##*/}
case "$rootbase" in sd[a-z]|vd[a-z]) ;; *) fail 'Unexpected root disk.';; esac
[ "${rootpart##*/}" = "${rootbase}2" ] &&
    [ "$(cat "$base/size")" = @DISK_SECTORS@ ] && [ "$(cat "$base/ro")" = 0 ] &&
    [ "$(cat "$base/${rootbase}1/start")" = @BOOT_START@ ] &&
    [ "$(cat "$base/${rootbase}1/size")" = @BOOT_SECTORS@ ] &&
    [ "$(cat "$rootpart/start")" = @ROOT_START@ ] && [ "$(cat "$rootpart/size")" = @ROOT_SECTORS@ ] ||
    fail 'Expected a writable @DISK_GIB@ GiB disk with @BOOT_MIB@ MiB boot and @ROOT_MIB@ MiB root partitions.'
disk=''
count=0
for dev in /sys/block/sd* /sys/block/vd* /sys/block/nvme*n*; do
    [ -d "$dev" ] || continue
    count=$((count + 1))
    [ "${dev##*/}" != "$rootbase" ] || continue
    candidate="/dev/${dev##*/}"
    [ -b "$candidate" ] && [ "$(cat "$dev/ro")" = 1 ] &&
        [ "$(head -c 10 "$candidate" 2>/dev/null)" = RESTORE.ID ] ||
        fail 'Detach old disks; attach only the read-only configuration carrier.'
    disk="$candidate"
done
[ "$count" = 2 ] && [ -n "$disk" ] || fail 'Expected exactly one system disk and one carrier.'
if [ "$#" -gt 0 ]; then
    [ "$#" = 1 ] && [ "$1" = "$disk" ] || fail 'Selected device is not the detected carrier.'
fi
sectors=$(cat "/sys/class/block/${disk##*/}/size" 2>/dev/null)
free_kib=$(df -k /tmp 2>/dev/null | awk 'END {print $4}')
case "$sectors" in ''|*[!0-9]*) fail 'Cannot measure the carrier.';; esac
case "$free_kib" in ''|*[!0-9]*) fail 'Cannot measure free space in /tmp.';; esac
[ "$sectors" -ge 8192 ] && [ "$free_kib" -ge $(( (sectors + 1) / 2 + 4096 )) ] ||
    fail 'Carrier size is invalid or /tmp needs more free space.'
root_kib=$(df -k / 2>/dev/null | awk 'END {print $4}')
case "$root_kib" in ''|*[!0-9]*) fail 'Cannot measure available root filesystem space.';; esac
[ "$root_kib" -ge @RESTORE_KIB@ ] || fail 'Not enough free space for the restored configuration.'

stage=$(mktemp -d /tmp/router-restore.XXXXXX) || fail 'Cannot create restore directory.'
cleanup() {
    rm -f "$stage/RESTORE.ID" "$stage/SHA256SUM" "$stage/RESTORE.TGZ" "$stage/members" \
        "$stage/detach-leaves" "$stage/ordinary-members" "$stage/checked-members"
    for table in passwd group shadow gshadow; do
        rm -f "$stage/incoming.$table" "$stage/original.$table" "$stage/merged.$table"
    done
    rmdir "$stage"
}
trap 'cleanup >/dev/null 2>&1' EXIT
trap 'fail "Restore interrupted."' HUP INT TERM
cd "$stage" || fail 'Cannot enter restore directory.'
tar -xf "$disk" RESTORE.ID SHA256SUM RESTORE.TGZ >/dev/null 2>&1 ||
    fail 'Cannot read carrier members.'
[ "$(wc -c < RESTORE.ID)" -eq @MARKER_BYTES@ ] && [ "$(cat RESTORE.ID)" = '@MARKER@' ] ||
    fail 'Invalid carrier marker.'
[ "$(wc -c < SHA256SUM)" -eq 78 ] && grep -Eq '^[0-9a-f]{64}  RESTORE\.TGZ$' SHA256SUM ||
    fail 'Invalid checksum manifest.'
sha256sum -c SHA256SUM >/dev/null 2>&1 || fail 'Restore archive checksum mismatch.'
tar -tzf RESTORE.TGZ > members 2>/dev/null || fail 'Restore archive is unreadable.'
state=/etc/.router-upgrade-restore
if [ -e "$state" ] || [ -L "$state" ]; then
    if [ ! -L "$state" ] && [ -d "$state" ] && [ -f "$state/done" ] &&
       [ ! -L "$state/done" ] && cmp -s "$state/done" SHA256SUM; then
        printf 'This carrier was already applied to this disk.\nRESTORE_OK\n'
        exit 0
    fi
    fail 'Previously interrupted or different restore found. Use the original disks or a fresh verified system disk.'
fi
[ ! -e /etc/AdGuardHome.yaml ] && [ ! -L /etc/AdGuardHome.yaml ] ||
    fail 'The target already contains AdGuard Home settings. Select the fresh imported system disk.'

# Check the *running target*, in addition to the builder's archive-link checks.
# A bind mount can redirect writes even where no path component is a symlink.
awk 'FNR==NR { mount=$5; gsub(/\\040/," ",mount); if (mount!="/") mounts[mount]=1; next }
    { path="/" $0; sub(/\/$/,"",path); while (path!="") {
        if (path in mounts) exit 1
        sub(/\/[^/]*$/,"",path)
    }}' /proc/self/mountinfo members || fail 'A restore path is mounted separately. Use a clean isolated system disk.'

: > detach-leaves || fail 'Cannot create destination preflight list.'
while IFS= read -r member; do
    case "$member" in etc/*|usr/*|www/*|root/*) ;; *) fail 'Unexpected archive path.';; esac
    case "/$member/" in */../*|*/./*) fail 'Unexpected archive traversal.';; esac
    leaf="/${member%/}"
    parent=${leaf%/*}
    while [ -n "$parent" ]; do
        if [ -L "$parent" ] || { [ -e "$parent" ] && [ ! -d "$parent" ]; }; then
            fail 'A restore path uses a non-directory or symlink parent on the target. Use a fresh verified disk.'
        fi
        parent=${parent%/*}
    done
    case "$leaf" in /etc/passwd|/etc/group|/etc/shadow|/etc/gshadow)
        [ ! -L "$leaf" ] && { [ ! -e "$leaf" ] || [ -f "$leaf" ]; } ||
            fail 'Unexpected target account database type.';;
    esac
    case "$member" in
        */)
            [ ! -L "$leaf" ] && { [ ! -e "$leaf" ] || [ -d "$leaf" ]; } ||
                fail 'Target directory type does not match the archive.';;
        *)
            if [ -L "$leaf" ]; then
                printf '%s\n' "$leaf" >> detach-leaves || fail 'Cannot record previous link.'
            elif [ -e "$leaf" ]; then
                [ -f "$leaf" ] || fail 'Target file type does not match the archive.'
                # Avoid overwriting a different name via an existing hardlink.
                count=$(ls -ldn "$leaf" | awk '{ print $2 }') || fail 'Cannot check the target file link count.'
                case "$count" in ''|*[!0-9]*) fail 'Unexpected target file link count.';; esac
                if [ "$count" -gt 1 ]; then
                    case "$leaf" in /etc/passwd|/etc/group|/etc/shadow|/etc/gshadow) continue;; esac
                    printf '%s\n' "$leaf" >> detach-leaves || fail 'Cannot record previous link.'
                fi
            fi;;
    esac
done < members

begin_restore() {
    mkdir "$state" || fail 'Cannot acquire the restore marker. Check for an earlier attempt.'
    sync || fail 'Cannot sync the restore marker.'
    while IFS= read -r leaf; do
        rm -f "$leaf" || fail 'Could not detach a target link. Reimport the clean replacement disk.'
    done < detach-leaves
}
# Package users and groups can be added in a new release. Merge the backed-up
# tables in private scratch first; never install the original unmixed tables.
for table in passwd group shadow gshadow; do
    grep -Fxq "etc/$table" members || continue
    [ ! -L "/etc/$table" ] && { [ ! -e "/etc/$table" ] || [ -f "/etc/$table" ]; } ||
        fail 'Unexpected target account table type.'
    tar -xzOf RESTORE.TGZ "etc/$table" > "incoming.$table" ||
        fail 'Cannot read backed-up account table.'
    baseline=/dev/null
    if [ -f "/etc/$table" ]; then
        cp -p "/etc/$table" "original.$table" && cp -p "original.$table" "merged.$table" ||
            fail 'Cannot stage original account table.'
        baseline="original.$table"
    else
        case "$table" in passwd|group) fail 'Base identity tables missing from the target.';; esac
        : > "merged.$table" || fail 'Cannot create private account table.'
    fi
    awk -F: -v OFS=: -v table="$table" '
        function valid_id(value) {
            return value ~ /^(0|[1-9][0-9]*)$/ && value+0 <= 4294967294
        }
        function members(backup, target,    set,list,i,n,name) {
            n=split(backup,list,","); for (i=1;i<=n;i++) set[list[i]]=1
            n=split(target,list,",")
            for (i=1;i<=n;i++) {
                name=list[i]
                if (name!="" && !(name in set) && !(name in source_users)) {
                    backup=backup (backup=="" ? "" : ",") name; set[name]=1
                }
            }
            return backup
        }
        BEGIN {
            if (table=="group" || table=="gshadow") {
                while ((getline line < "incoming.passwd") > 0) {
                    split(line,record,":"); source_users[record[1]]=1
                }
                close("incoming.passwd")
            }
        }
        {
            if ($1=="" || $1 ~ /[[:space:]\/]/ || $0 ~ /[[:cntrl:]]/ ||
                (table=="passwd" && NF!=7) || (table=="group" && NF!=4) ||
                (table=="shadow" && NF!=9) || (table=="gshadow" && NF!=4)) bad=1
            if ((table=="passwd" || table=="group") && !valid_id($3)) bad=1
            if (table=="passwd" && !valid_id($4)) bad=1
        }
        FILENAME==ARGV[1] {
            if ($1 in names) bad=1
            names[$1]=1; target_id[$1]=$3; target_field4[$1]=$4; id_in_target[$3]=1
            original[++n]=$0; original_name[n]=$1; next
        }
        {
            if (++seen[$1] > 1) bad=1
            if (table=="passwd" || table=="group") {
                if ($1 in names) {
                    if ($3!=target_id[$1] || (table=="passwd" && $4!=target_field4[$1])) bad=1
                } else if ($3 in id_in_target || $3 in id_in_backup || $3==0) bad=1
                id_in_backup[$3]=1
            }
            if ($1 in names && (table=="group" || table=="gshadow")) {
                $4=members($4, target_field4[$1])
                if (table=="gshadow") $3=members($3, target_id[$1])
            }
            print
        }
        END {
            if (bad) exit 1
            for (i=1;i<=n;i++) if (!(original_name[i] in seen)) print original[i]
        }
    ' "$baseline" "incoming.$table" > "merged.$table" ||
        fail 'Conflicting or invalid account names or IDs. Keep old disks and review locally.'
done
if [ -f incoming.passwd ]; then
    groups=/etc/group
    [ ! -f merged.group ] || groups=merged.group
    awk -F: 'FILENAME==ARGV[1] {ids[$3]=1; next} !($4 in ids) {exit 1}' "$groups" incoming.passwd ||
        fail 'A backed-up user has an unknown primary group. Review both account tables.'
fi
# Use the positive file list supported by the firmware's BusyBox tar. Verify
# its actual selection, including directory matches, before restoring anything.
awk '!/^etc\/(passwd|group|shadow|gshadow)$/' members > ordinary-members ||
    fail 'Cannot stage restore file list.'
tar -T ordinary-members -tzf RESTORE.TGZ > checked-members 2>/dev/null &&
    cmp -s ordinary-members checked-members ||
    fail 'The target tar cannot select the configuration payload safely.'
# APPLY_RESTORE: first ordinary filesystem write.
begin_restore
tar -C / -xzpf "$stage/RESTORE.TGZ" -T "$stage/ordinary-members" >/dev/null 2>&1 || fail 'Configuration restore failed.'
install_table() {
    temp_table=$(mktemp "/etc/.router-upgrade-$1.XXXXXX") || return 1
    if cp -p "$2" "$temp_table" && mv -f "$temp_table" "/etc/$1"; then return 0; fi
    rm -f "$temp_table"
    return 1
}
committed=''
for table in group gshadow shadow passwd; do
    [ -f "merged.$table" ] || continue
    if ! install_table "$table" "merged.$table"; then
        for prior in $committed; do
            if [ -f "original.$prior" ]; then
                install_table "$prior" "original.$prior" || fail 'Account rollback failed. Re-import the fresh disk.'
            else
                rm -f "/etc/$prior" || fail 'Account rollback failed. Re-import the fresh disk.'
            fi
        done
        fail 'Could not install the merged account tables. Re-import the fresh disk.'
    fi
    committed="$table $committed"
done
# Account transaction complete.
for config in network dhcp firewall dropbear openclash; do
    uci -q export "$config" >/dev/null ||
        fail 'Restored UCI configuration is invalid. Keep old disks and reimport a clean system disk.'
done
/usr/bin/AdGuardHome/AdGuardHome --check-config -c /etc/AdGuardHome.yaml \
    -w /usr/bin/AdGuardHome >/dev/null 2>&1 ||
    fail 'Restored AdGuard Home configuration could not be validated. Check the saved YAML and local dependencies.'
# The release's BusyBox may have no timeout applet. Bound this local probe
# while the two tested NICs are disconnected and keep private output silent.
/etc/openclash/core/clash_meta -v >/dev/null 2>&1 &
core_pid=$!
(sleep 15 && kill -KILL "$core_pid" 2>/dev/null) &
watchdog=$!
wait "$core_pid"; core_status=$?
kill "$watchdog" 2>/dev/null || :
wait "$watchdog" 2>/dev/null || :
[ "$core_status" = 0 ] ||
    fail 'Restored OpenClash core could not execute on this system. Check the backed-up x86-64 core.'
sync && cp SHA256SUM "$state/done.tmp" && mv "$state/done.tmp" "$state/done" && sync ||
    fail 'Could not commit the completed restore.'
printf 'RESTORE_OK\n'
"""


class _HashingReader:
    def __init__(self, source):
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size):
        data = self.source.read(size)
        self.digest.update(data)
        return data


def _member(name, size):
    info = tarfile.TarInfo(name)
    info.mode = 0o600
    info.size = size
    return info


def validate_version(version):
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,3}", version):
        raise ValueError("恢复盘需要明确的稳定版版本号，例如 25.12.2。")


def carrier_marker(layout=DEFAULT_LAYOUT):
    if not isinstance(layout, Layout):
        raise ValueError("请选择有效的目标磁盘布局。")
    if layout == DEFAULT_LAYOUT:
        return "IMWRT-RESTORE-V2"
    return f"IMWRT-RESTORE-V3 {layout.disk_gib} {layout.boot_mib}"


def create_carrier(archive_path, output_path, version, unpacked_bytes, layout=DEFAULT_LAYOUT):
    """Write a new carrier. Raise FileExistsError if the output already exists."""
    validate_version(version)
    if not isinstance(unpacked_bytes, int) or unpacked_bytes <= 0:
        raise ValueError("恢复归档长度无效。")
    required_kib = (unpacked_bytes + 1023) // 1024 + 8192
    marker_text = carrier_marker(layout)
    marker = (marker_text + "\n").encode("ascii")
    (boot_start, boot_sectors), (root_start, root_sectors) = layout.partitions
    values = {
        "VERSION": version, "RESTORE_KIB": required_kib,
        "MARKER": marker_text, "MARKER_BYTES": len(marker),
        "DISK_GIB": layout.disk_gib, "BOOT_MIB": layout.boot_mib, "ROOT_MIB": layout.root_mib,
        "DISK_SECTORS": layout.disk_bytes // 512, "BOOT_START": boot_start,
        "BOOT_SECTORS": boot_sectors, "ROOT_START": root_start, "ROOT_SECTORS": root_sectors,
    }
    runner = re.sub(rb"@([A-Z_]+)@", lambda m: str(values[m[1].decode()]).encode("ascii"), _RUN_SCRIPT)
    manifest_tail = b"  RESTORE.TGZ\n"
    placeholder = b"0" * 64 + manifest_tail
    mib = 1024 * 1024

    with open(archive_path, "rb") as source:
        carrier = open(output_path, "xb", opener=lambda p, f: os.open(p, f, 0o600))
        try:
            with carrier:
                with tarfile.open(fileobj=carrier, mode="w:", format=tarfile.USTAR_FORMAT) as tar:
                    tar.addfile(_member("RESTORE.ID", len(marker)), io.BytesIO(marker))
                    # Each USTAR header occupies one block. Fill in the digest
                    # after reading the archive, so it describes exactly the bytes copied.
                    checksum_offset = carrier.tell() + tarfile.BLOCKSIZE
                    tar.addfile(_member("SHA256SUM", len(placeholder)), io.BytesIO(placeholder))
                    reader = _HashingReader(source)
                    tar.addfile(_member("RESTORE.TGZ", os.fstat(source.fileno()).st_size), reader)
                    tar.addfile(_member("RUN.SH", len(runner)), io.BytesIO(runner))

                used = carrier.tell()
                padded = max(4 * mib, ((used + mib - 1) // mib) * mib)
                carrier.truncate(padded)
                carrier.seek(checksum_offset)
                carrier.write(reader.digest.hexdigest().encode("ascii"))
        except BaseException:
            os.unlink(output_path)
            raise
