#!/usr/bin/env bash
# Boot the final standalone QCOW2 with SeaBIOS and one VirtIO SCSI controller.
# Guest writes go to a temporary snapshot. No serial logs are saved.
set -euo pipefail
export LC_ALL=C
umask 077

[[ $# -ge 2 && -f $1 && $2 =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Usage: $0 IMAGE.qcow2 VERSION [MANIFEST] [--disk-gib N] [--boot-mib N]" >&2; exit 2; }
engine=$(cd -- "$(dirname -- "$0")" && pwd -P)
version=$2
source_image=$(realpath -e -- "$1")
shift 2
manifest=
if (( $# )) && [[ $1 != --* ]]; then manifest=$(realpath -e -- "$1"); shift; fi
command -v qemu-system-x86_64 >/dev/null || { echo 'qemu-system-x86 is required' >&2; exit 2; }
firmware=/usr/share/seabios/bios-256k.bin
[[ -r $firmware ]] || { echo 'Debian/Ubuntu SeaBIOS firmware is required' >&2; exit 2; }
scratch=$(mktemp -d)
trap 'rm -f -- "$scratch/disk.qcow2"; rmdir -- "$scratch"' EXIT
ln -s -- "$source_image" "$scratch/disk.qcow2"
cd -- "$scratch"
# Bind the base disk read-only by means of QEMU's temporary snapshot. QEMU uses
# TMPDIR for that snapshot. No host shares, VM network or external monitor.
PYTHONPATH="$engine" TMPDIR="$PWD" python3 -B - "$firmware" "$version" "$manifest" "$@" <<'PY'
import argparse
import hashlib
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

from layout import Layout, SECTOR, add_layout_arguments

parser = argparse.ArgumentParser()
add_layout_arguments(parser)
args = parser.parse_args(sys.argv[4:])
try:
    layout = Layout(args.disk_gib, args.boot_mib)
except ValueError as exc:
    parser.error(str(exc))

command = [
    "qemu-system-x86_64", "-no-user-config", "-machine", "pc,accel=tcg",
    "-cpu", "max", "-m", "2048", "-smp", "2", "-bios", sys.argv[1],
    "-drive", "file=disk.qcow2,if=none,id=osdisk,format=qcow2,snapshot=on",
    "-device", "virtio-scsi-pci,id=scsi0",
    "-device", "scsi-hd,bus=scsi0.0,channel=0,scsi-id=0,lun=0,drive=osdisk,bootindex=1",
    "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio",
    "-no-reboot",
]
# Keep each interactive command short for BusyBox line editing and split the
# success marker so serial echo cannot pass the test.
checks = [
    ('. /etc/openwrt_release && [ "$DISTRIB_ID" = ImmortalWrt ] && [ "$DISTRIB_RELEASE" = "' + sys.argv[2] + '" ]').encode("ascii"),
    b'[ ! -d /sys/firmware/efi ] && [ "$(cat /proc/1/comm)" = procd ] && ubus call system board >/dev/null',
    b'[ -r /lib/functions.sh ] && [ -x /etc/init.d/openclash ] && /bin/bash -n /etc/init.d/openclash',
    b'[ -x /etc/init.d/dnsmasq ] && [ -x /etc/init.d/odhcpd ] && uci -q show dhcp >/dev/null',
    b'/etc/init.d/AdGuardHome enabled && /usr/bin/AdGuardHome/AdGuardHome --version 2>&1 | grep -Eq "AdGuard Home.*v[0-9]"',
    b"""awk '$2=="/" && $3=="ext4" {ok=1} END {exit !ok}' /proc/mounts""",
    b'[ -b /dev/sda1 ] && [ -b /dev/sda2 ] && [ ! -b /dev/sdb ]',
    b"""awk '$2=="/boot" {b++} $2=="/mnt/sda1" {m++} END {exit !(b && !m)}' /proc/mounts""",
    # Only the snapshot is writable. A synthetic upstream represents the
    # restored proxy's DNS port; no real profiles, credentials or WAN are used.
    b"command -v dig >/dev/null && command -v dnsmasq >/dev/null",
    b"ip link set dev lo up && ip addr replace 127.0.0.1/8 dev lo",
    b"""[ -s /tmp/qa-upstream.pid ] || dnsmasq -C /dev/null -p 7874 -a 127.0.0.1 --bind-interfaces -n -R --address=/upgrade-probe.example.net/9.9.9.9 -x /tmp/qa-upstream.pid""",
    b"""[ "$(dig +short +time=2 +tries=1 @127.0.0.1 -p 7874 upgrade-probe.example.net A)" = 9.9.9.9 ]""",
    b"""printf '%s\\n' 'http:' '  address: 127.0.0.1:3000' 'dns:' '  bind_hosts: [127.0.0.1]' '  port: 5335' '  upstream_dns: ["127.0.0.1:7874"]' 'schema_version: 34' >/etc/AdGuardHome.yaml""",
    b"/etc/init.d/AdGuardHome restart",
    b"""for t in 1 2 3 4 5; do dig +short +time=1 +tries=1 @127.0.0.1 -p 5335 upgrade-probe.example.net A 2>/dev/null | grep -qx 9.9.9.9 && break; sleep 1; done; dig +short +time=1 +tries=1 @127.0.0.1 -p 5335 upgrade-probe.example.net A | grep -qx 9.9.9.9""",
    b"""uci -q delete dhcp.@dnsmasq[0].server; uci add_list 'dhcp.@dnsmasq[0].server=127.0.0.1#5335' && uci set 'dhcp.@dnsmasq[0].noresolv=1' && /etc/init.d/dnsmasq restart""",
    b"""for t in 1 2 3 4 5; do dig +short +time=1 +tries=1 @127.0.0.1 upgrade-probe.example.net A 2>/dev/null | grep -qx 9.9.9.9 && break; sleep 1; done; dig +short +time=1 +tries=1 @127.0.0.1 upgrade-probe.example.net A | grep -qx 9.9.9.9""",
]
checks.append(f'[ "$(cat /sys/class/block/sda/size)" = {layout.disk_bytes // SECTOR} ]'.encode("ascii"))
for index, (start, length) in enumerate(layout.partitions, 1):
    path = f"/sys/class/block/sda{index}"
    checks.append(f'[ "$(cat {path}/start)" = {start} ] && [ "$(cat {path}/size)" = {length} ]'.encode("ascii"))
package_count = 0
if sys.argv[3]:
    pairs = Path(sys.argv[3]).read_bytes().splitlines()
    if not pairs or any(not re.fullmatch(rb"[A-Za-z0-9+_.-]+ - [!-~]+", p) for p in pairs):
        sys.exit("Invalid installed package manifest format")
    package_count = len(pairs)
    expected = hashlib.sha256(b"\n".join(sorted(pairs)) + b"\n").hexdigest().encode()
    # Read the actual installed database from the running guest. APK's binary
    # DB format need not be interpreted or guessed by this host program.
    checks += [
        b"apk --no-network query --installed --fields name,version --format json '*' >/tmp/qa-pkgs.json",
        b"""jsonfilter -i /tmp/qa-pkgs.json -e '@[*].name' >/tmp/qa-names""",
        b"""jsonfilter -i /tmp/qa-pkgs.json -e '@[*].version' >/tmp/qa-versions""",
        b"""awk 'NR==FNR {a[NR]=$0; next} {print a[FNR] " - " $0}' /tmp/qa-names /tmp/qa-versions | LC_ALL=C sort >/tmp/qa-manifest""",
        b"sha256sum /tmp/qa-manifest | grep -q '^" + expected + b" '",
    ]
probe = [b'p() {']
for n, check in enumerate(checks, start=1):
    probe.append(check + b" || { printf '\\nCHECK_FAIL_%d\\n' " + str(n).encode() + b'; return 1; }')
probe += [
    b"""awk '$2=="/boot" {b++} $2=="/mnt/sda1" {m++} END {printf "\\nVM_MOUNT_COUNTS=%d,%d\\n",b,m}' /proc/mounts""",
    b"printf '\\nBIOS_VM_%s\\n' OK",
    b'}', b'p',
]
guest = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, bufsize=0)
recent = b""
deadline = time.monotonic() + 240
next_probe = float("inf")
saw_kernel = False
saw_console = False
saw_login = False
last_failed = None
try:
    with selectors.DefaultSelector() as streams:
        streams.register(guest.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if streams.select(timeout=1):
                chunk = os.read(guest.stdout.fileno(), 8192)
                if not chunk:
                    break
                recent = (recent + chunk)[-32768:]
                saw_kernel |= b"Linux version " in recent
                saw_console |= b"activate this console" in recent or b"root@" in recent
                saw_login |= b"login:" in recent
                failed = re.findall(rb"(?:^|[\r\n])CHECK_FAIL_(\d+)[\r\n]", recent)
                if failed and failed[-1] != last_failed:
                    last_failed = failed[-1]
                    print("Guest check needs retry: " + last_failed.decode(), file=sys.stderr, flush=True)
                if re.search(rb"(?:^|[\r\n])BIOS_VM_OK[\r\n]", recent):
                    counts = re.search(rb"(?:^|[\r\n])VM_MOUNT_COUNTS=(\d+),(\d+)[\r\n]", recent)
                    if counts:
                        print("Guest mount entries: /boot=%s /mnt/sda1=%s" % (counts[1].decode(), counts[2].decode()))
                    if package_count:
                        print(f"Guest APK database matches all {package_count} names and versions in the manifest.")
                    print(f"Guest /dev/sda capacity and both partition starts and lengths match "
                          f"{layout.disk_gib} GiB, boot {layout.boot_mib} MiB, root {layout.root_mib} MiB.")
                    print(f"PASS: SeaBIOS/VirtIO SCSI booted ImmortalWrt {sys.argv[2]}; ext4, procd, ubus, OpenClash init, and DNS via dnsmasq:53 -> native AdGuardHome:5335 -> synthetic upstream:7874 checked.")
                    sys.exit(0)
                if next_probe == float("inf") and (
                    b"activate this console" in recent or b"root@" in recent or
                    re.search(rb"procd[^\r\n]*init complete", recent)
                ):
                    guest.stdin.write(b"\r")
                    next_probe = time.monotonic() + 2
            if time.monotonic() >= next_probe:
                for line in probe:
                    guest.stdin.write(line + b"\r")
                    time.sleep(0.08)
                next_probe = time.monotonic() + 10
except BrokenPipeError:
    pass
finally:
    if guest.poll() is None:
        guest.terminate()
        try:
            guest.wait(timeout=5)
        except subprocess.TimeoutExpired:
            guest.kill()
            guest.wait()
print(f"FAIL: guest proof missing (kernel={saw_kernel}, console={saw_console}, login={saw_login}).", file=sys.stderr)
failures = re.findall(rb"(?:^|[\r\n])CHECK_FAIL_(\d+)[\r\n]", recent)
if failures:
    print("Failed guest check: " + failures[-1].decode(), file=sys.stderr)
sys.exit(1)
PY
