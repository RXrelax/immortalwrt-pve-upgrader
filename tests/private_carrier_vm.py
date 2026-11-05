"""Exercise the offline restore with public firmware and a generated synthetic archive."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time

from engine.layout import DEFAULT_LAYOUT, Layout
from engine.private_restore import prepare_private
from fixture_elf import synthetic_core


def synthetic_carrier(version, layout=DEFAULT_LAYOUT):
    """Use the same admission/review/archive path as the GUI, with no real data."""
    core = synthetic_core()
    members = {
        "etc/hosts": b"127.0.0.1 localhost\n127.0.0.2 synthetic-restore-v1\n",
        "etc/netdata/qa/probe.conf": b"synthetic target preflight\n",
        "etc/config/network": b"config interface 'loopback'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.1'\n option netmask '255.0.0.0'\n",
        "etc/config/firewall": b"config defaults\n option input 'REJECT'\n option output 'ACCEPT'\n",
        "etc/config/dhcp": b"config dnsmasq\n option noresolv '1'\n",
        "etc/config/dropbear": b"config dropbear\n option Port '22'\n",
        "etc/config/openclash": b"config openclash 'config'\n option enable '0'\n option config_path '/etc/openclash/config/wizard.yaml'\n",
        "etc/openclash/config/wizard.yaml": b"proxies: []\n",
        "etc/openclash/core/clash_meta": core,
        "etc/AdGuardHome.yaml": (b"http:\n  address: 127.0.0.1:3000\ndns:\n  bind_hosts: [127.0.0.1]\n"
                                b"  port: 5335\n  upstream_dns: [\"127.0.0.1:7874\"]\nfilters:\n"
                                b"  - enabled: true\n    id: 123\n    url: https://example.invalid/rules\nschema_version: 34\n"),
        "usr/bin/AdGuardHome/data/filters/123.txt": b"||wizard.invalid^\n",
        "www/luci-static/argon/background/wizard-test.png": b"synthetic fixture\n",
        "etc/passwd": b"root:x:0:0:root:/root:/bin/ash\nwizard-test:x:30001:30001:test:/tmp:/bin/false\n",
        "etc/group": b"root:x:0:\nwizard-test:x:30001:\n",
        "etc/config/fstab": b"config mount\n option target '/overlay'\n",
    }
    if os.environ.get("ROUTER_TEST_BAD_YAML") == "1":
        members["etc/AdGuardHome.yaml"] = b"dns: [ deliberate incomplete fixture\n"
    with tarfile.open("synthetic.tgz","w:gz") as tar:
        for name, data in members.items():
            m = tarfile.TarInfo(name)
            m.size, m.mode = len(data), 0o755 if name.endswith("/clash_meta") else 0o644
            tar.addfile(m, io.BytesIO(data))
    output = prepare_private(Path("synthetic.tgz"), Path.cwd(), version, None, lambda paths: True, print, layout)
    os.rename(output["raw"],"carrier.raw")


def digest(path):
    with open(path, "rb") as src:
        return hashlib.file_digest(src, "sha256").hexdigest()


def unplug_carrier():
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(20)
        sock.connect("qmp.sock")
        with sock.makefile("rwb", buffering=0) as wire:
            assert "QMP" in json.loads(wire.readline())
            wire.write(b'{"execute":"qmp_capabilities"}\n')
            assert "return" in json.loads(wire.readline())
            wire.write(b'{"execute":"device_del","arguments":{"id":"carrier-device"}}\n')
            while True:
                reply = json.loads(wire.readline())
                if "error" in reply:
                    raise RuntimeError("carrier detach failed")
                if reply.get("event") == "DEVICE_DELETED" and reply.get("data", {}).get("device") == "carrier-device":
                    return


carrier_checks = [
    'ubus -t 75 wait_for network.interface && { i=0; while [ -e /tmp/.config_pending ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i+1)); done; [ ! -e /tmp/.config_pending ]; }',
    'set -- /sys/block/sd*; [ "$#" = 2 ]',
    'for dev in /sys/block/sd*; do if [ "$(cat "$dev/ro")" = 1 ]; then carrier=/dev/${dev##*/}; else system=${dev##*/}; fi; done',
    '[ "$(head -c 10 "$carrier")" = RESTORE.ID ] && umask 077 && tar -xf "$carrier" -C /tmp RUN.SH',
]
restore_checks = [
    # Temporarily limit the real tmpfs capacity while leaving its files visible.
    'set -- $(df -k /tmp | awk \'END {print $2,$3}\'); orig=$1; small=$(($2+1024))',
    'mount -t tmpfs -o "remount,size=${small}k" tmpfs /tmp',
    'sh /tmp/RUN.SH "$carrier" >/tmp/guard.log 2>&1; guard=$?; mount -t tmpfs -o "remount,size=${orig}k" tmpfs /tmp',
    '[ "$guard" -ne 0 ] && grep -q "needs more free space" /tmp/guard.log && ! grep -q synthetic-restore-v1 /etc/hosts',
    'mkdir -p /etc/netdata /tmp/wizard-probe && ln -s /tmp/wizard-probe /etc/netdata/qa',
    '! sh /tmp/RUN.SH >/tmp/fence.log 2>&1 && grep -q "symlink parent" /tmp/fence.log',
    '[ ! -e /etc/.router-upgrade-restore ] && [ ! -e /tmp/wizard-probe/probe.conf ] && ! grep -q synthetic-restore /etc/hosts',
    'rm /etc/netdata/qa && mkdir /etc/netdata/qa && echo original >/etc/netdata/qa/original && ln /etc/netdata/qa/original /etc/netdata/qa/probe.conf',
    'echo synthetic-active >/etc/AdGuardHome.yaml && ! sh /tmp/RUN.SH >/tmp/fresh.log 2>&1 && grep -q "fresh imported" /tmp/fresh.log',
    'grep -qx synthetic-active /etc/AdGuardHome.yaml && [ ! -e /etc/.router-upgrade-restore ] && rm /etc/AdGuardHome.yaml',
    'tar -xOf "$carrier" RUN.SH > /tmp/run-restore.sh && [ "$(sha256sum </tmp/RUN.SH)" = "$(sha256sum </tmp/run-restore.sh)" ]',
    'sh /tmp/run-restore.sh "$carrier" >/tmp/restore-run.log && grep -qx RESTORE_OK /tmp/restore-run.log',
    'grep -qx original /etc/netdata/qa/original && grep -qx "synthetic target preflight" /etc/netdata/qa/probe.conf',
    'sh /tmp/RUN.SH >/tmp/repeat.log && grep -q "already applied" /tmp/repeat.log',
    'grep -q synthetic-restore-v1 /etc/hosts && id nobody >/dev/null && [ "$(id -u wizard-test)" = 30001 ]',
    '[ "$(cat /www/luci-static/argon/background/wizard-test.png)" = "synthetic fixture" ]',
    '[ "$(cat /usr/bin/AdGuardHome/data/filters/123.txt)" = "||wizard.invalid^" ]',
    '[ "$(uci -q get openclash.config.config_path)" = "/etc/openclash/config/wizard.yaml" ]',
    'cat /proc/sys/kernel/random/boot_id > /etc/router-migration-test.boot && sync',
]
after_reboot = [
    '[ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat /etc/router-migration-test.boot)" ]',
    'set -- /sys/block/sd*; [ "$#" = 1 ] && [ ! -e /tmp/restore-run.log ]',
    'grep -q synthetic-restore-v1 /etc/hosts && id nobody >/dev/null && [ "$(id -u wizard-test)" = 30001 ]',
    '[ "$(cat /www/luci-static/argon/background/wizard-test.png)" = "synthetic fixture" ]',
    '[ "$(cat /usr/bin/AdGuardHome/data/filters/123.txt)" = "||wizard.invalid^" ]',
    '[ "$(cat /proc/1/comm)" = procd ] && ubus call system board >/dev/null',
]

failed_restore = [
    '! sh /tmp/RUN.SH "$carrier" >/tmp/bad.log 2>&1 && grep -q "could not be validated" /tmp/bad.log',
    '[ -d /etc/.router-upgrade-restore ] && [ ! -e /etc/.router-upgrade-restore/done ] && ! grep -qx RESTORE_OK /tmp/bad.log',
    '! sh /tmp/RUN.SH "$carrier" >/tmp/retry.log 2>&1 && grep -q "Previously interrupted" /tmp/retry.log',
]
mismatched_restore = [
    '! sh /tmp/RUN.SH "$carrier" >/tmp/mismatch.log 2>&1 && grep -q "Expected a writable .* partitions" /tmp/mismatch.log',
    '[ ! -e /etc/.router-upgrade-restore ] && ! grep -q synthetic-restore /etc/hosts && ! grep -qx RESTORE_OK /tmp/mismatch.log',
]


def send_checks(guest, checks):
    lines = ["run_test() {"]
    for n, check in enumerate(checks, 1):
        lines.append(check + f" || {{ printf '\\nRESTORE_FAIL_%s\\n' {n}; return 1; }}")
    lines += ["printf '\\nRESTORE_%s\\n' PASSED", "}", "run_test"]
    for line in lines:
        guest.stdin.write(line.encode() + b"\r")
        time.sleep(0.10)


def run_stage(guest, checks, new_boot=False):
    recent = b""
    next_probe = float("inf")
    start = time.monotonic()
    deadline = start + 210
    first_console = first_restart = False
    with selectors.DefaultSelector() as output:
        output.register(guest.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if output.select(timeout=1):
                chunk = os.read(guest.stdout.fileno(), 8192)
                if not chunk:
                    raise RuntimeError("QEMU terminated")
                recent = (recent + chunk)[-32768:]
                if re.search(rb"(?:^|[\r\n])RESTORE_PASSED[\r\n]", recent):
                    return
                failed = re.search(rb"(?:^|[\r\n])RESTORE_FAIL_(\d+)[\r\n]", recent)
                if failed:
                    errors = re.findall(rb"(?:^|[\r\n])(Restore stopped: [^\r\n]+)", recent)
                    detail = ": " + errors[-1].decode(errors="replace") if errors else ""
                    raise RuntimeError("failed guest check " + failed[1].decode() + detail + ": " + repr(recent[-600:]))
                if new_boot and not first_restart and re.search(rb"(?i)restart|rebooting|booting from", recent):
                    print("Observed a guest restart/boot message.", flush=True)
                    first_restart = True
                ready = (b"activate this console" in recent or
                         (b"root@" in recent and (not new_boot or time.monotonic() - start > 15)) or
                         re.search(rb"procd[^\r\n]*init complete", recent))
                if next_probe == float("inf") and ready:
                    first_console = True
                    guest.stdin.write(b"\r")
                    next_probe = time.monotonic() + 2
            if time.monotonic() >= next_probe:
                guest.stdin.write(b"\r")
                send_checks(guest, checks)
                next_probe = time.monotonic() + 15
    # The test harness creates all guest data itself; show just the tail of
    # that synthetic serial console when the second-stage proof times out.
    raise RuntimeError(f"serial proof timed out (restart={first_restart}, console={first_console}): " +
                       repr(recent[-1400:]))


def main():
    public = Path("/firmware.qcow2")
    original = digest(public)
    layout = Layout(int(os.environ.get("ROUTER_TEST_DISK_GIB", DEFAULT_LAYOUT.disk_gib)),
                    int(os.environ.get("ROUTER_TEST_BOOT_MIB", DEFAULT_LAYOUT.boot_mib)))
    expected = [("/sys/block/$system/size", layout.disk_bytes // 512)]
    for i, (start, sectors) in enumerate(layout.partitions, 1):
        part = f"/sys/class/block/${{system}}{i}"
        expected.extend([(f"{part}/start", start), (f"{part}/size", sectors)])
    geometry = " && ".join(f'[ "$(cat {path})" = {value} ]' for path, value in expected)
    mismatch = os.environ.get("ROUTER_TEST_EXPECT_MISMATCH") == "1"
    preflight = carrier_checks + [f"! {{ {geometry}; }}" if mismatch else geometry]
    with tempfile.TemporaryDirectory() as scratch:
        os.chdir(scratch)
        synthetic_carrier(os.environ["ROUTER_TEST_RELEASE"], layout)
        carrier_hash = digest("carrier.raw")
        shutil.copyfile(public, "disposable.qcow2")
        command = [
            "qemu-system-x86_64", "-no-user-config", "-machine", "pc,accel=tcg",
            "-cpu", "max", "-m", "2048", "-smp", "2", "-bios", "/usr/share/seabios/bios-256k.bin",
            "-drive", "file=disposable.qcow2,if=none,id=osdisk,format=qcow2",
            "-device", "virtio-scsi-pci,id=scsi0",
            "-device", "scsi-hd,bus=scsi0.0,scsi-id=0,lun=0,drive=osdisk,bootindex=1",
            "-nic", "none", "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-qmp", "unix:qmp.sock,server=on,wait=off",
        ]
        carrier_args = ["-drive", "file=carrier.raw,if=none,id=carrier,format=raw,readonly=on",
                        "-device", "scsi-hd,bus=scsi0.0,scsi-id=1,lun=0,drive=carrier,id=carrier-device"]
        if mismatch:
            stages = [(command + carrier_args, preflight + mismatched_restore, "wrong geometry rejected before restore")]
        elif os.environ.get("ROUTER_TEST_BAD_YAML") == "1":
            stages = [(command + carrier_args, preflight + failed_restore, "invalid ADH config and interrupted retry refused")]
        else:
            stages = [(command + carrier_args, preflight + restore_checks, "RESTORE_OK and guard checks; cold poweroff"),
                      (command, after_reboot, "independent cold boot without carrier, new boot ID and persisted files")]
        for args, checks, result in stages:
            with subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, bufsize=0) as guest:
                try:
                    run_stage(guest, checks)
                    guest.stdin.write(b"sync; poweroff\r")
                    if guest.wait(timeout=90):
                        raise RuntimeError("guest poweroff failed")
                finally:
                    if guest.poll() is None:
                        guest.kill()
                        guest.wait()
            print(f"PASS: {result}.", flush=True)
        if original != digest(public) or carrier_hash != digest("carrier.raw"):
            raise RuntimeError("an input disk changed")
        os.chdir("/")
        print("PASS: both disk hashes unchanged.")


if __name__ == "__main__":
    main()
