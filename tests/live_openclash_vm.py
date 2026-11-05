"""Offline SeaBIOS integration using a public pinned Mihomo binary and two isolated Ethernet wires.

Run inside the boot-test container with --network none. Supply the release
QCOW2 at /firmware.qcow2, the verified public core at /fixtures/mihomo, and
set ROUTER_TEST_RELEASE. Both input files must be read-only. Synthetic backup
contents, including all network addresses, are constructed below.

The public fixture is MetaCubeX/mihomo v1.19.33, release file
mihomo-linux-amd64-compatible-v1.19.33.gz, GitHub release SHA-256
386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6.
Mount its uncompressed bytes as /fixtures/mihomo, and OpenClash 0.48.002's
shipped /etc/config/openclash from its public package as /fixtures/uci.
The default redir-host test includes two cold boots. Use --fake-ip for an
independent restore and LAN-side policy check in that mode.
"""

import argparse
import base64
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

from private_carrier_vm import digest


APP = Path(__file__).resolve().parents[1]
PINNED_MIHOMO = "817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f"
LAN_MAC, WAN_MAC = (bytes.fromhex(x) for x in ("020000000010", "020000000020"))
CLIENT_MAC, GATEWAY_MAC = (bytes.fromhex(x) for x in ("020000000011", "020000000021"))
# OpenClash's default local-network exclusions cover RFC1918 LAN space. The
# simulated WAN uses TEST-NET, and neither interface can reach a real network.
LAN, CLIENT, GATEWAY = ("10.77.0.1", "10.77.0.50", "192.0.2.1")
# A response value only. All packets stay on the simulated local Ethernet wire.
ANSWER_IP = "9.9.9.9"
RESULT = socket.inet_aton(ANSWER_IP)


def ipv4_udp(src, dst, sport, dport, data):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(udp),
            1,
            0,
            64,
            17,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
    )
    value = sum(struct.unpack("!10H", ip))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    struct.pack_into("!H", ip, 10, ~value & 0xFFFF)
    return bytes(ip) + udp


def dns_query(name):
    qname = (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
        )
        + b"\0"
    )
    return bytes.fromhex("123401000001000000000000") + qname + struct.pack("!HH", 1, 1)


class Wire:
    """QEMU socket netdev framed Ethernet. The only peer is this in-container fixture."""

    def __init__(self, wan):
        self.wan = wan
        self.guest_mac, self.mac = (
            (WAN_MAC, GATEWAY_MAC) if wan else (LAN_MAC, CLIENT_MAC)
        )
        self.ip = GATEWAY if wan else CLIENT
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.lock = threading.Lock()
        self.answer = threading.Event()
        self.expected_answer = RESULT
        self.offer = threading.Event()
        self.ack = threading.Event()
        self.forwarded = threading.Event()
        self.forward_source = ""
        self.offered = None
        self.queries = set()
        self.peer = None
        threading.Thread(target=self.listen, daemon=True).start()

    def send(self, packet):
        if self.peer is not None:
            with self.lock:
                self.peer.sendall(struct.pack("!I", len(packet)) + packet)

    def incoming(self, pkt):
        if len(pkt) < 42:
            return
        if (
            pkt[12:14] == b"\x08\x06"
            and pkt[20:22] == b"\0\1"
            and pkt[38:42] == socket.inet_aton(self.ip)
        ):
            arp = pkt[14:20] + b"\0\2" + self.mac + pkt[38:42] + pkt[22:28] + pkt[28:32]
            self.send(pkt[6:12] + self.mac + b"\x08\x06" + arp)
            return
        if pkt[12:14] != b"\x08\x00" or pkt[23] != 17:
            return
        off = 14 + 4 * (pkt[14] & 15)
        if len(pkt) < off + 20:
            return
        sport, dport, length = struct.unpack_from("!HHH", pkt, off)
        dns = pkt[off + 8 : off + length]
        if self.wan and dport == 10080 and dns == b"routerupgrade-wan-probe":
            self.forward_source = socket.inet_ntoa(pkt[26:30])
            reply = ipv4_udp(
                self.ip, self.forward_source, 10080, sport, b"routerupgrade-wan-answer"
            )
            self.send(pkt[6:12] + self.mac + b"\x08\x00" + reply)
            return
        if not self.wan:
            if sport == 10080 and dport == 34568 and dns == b"routerupgrade-wan-answer":
                self.forwarded.set()
            if (
                sport == 67
                and dport == 68
                and len(dns) > 240
                and dns[0] == 2
                and dns[4:8] == b"RUQA"
                and dns[28:34] == CLIENT_MAC
                and dns[236:240] == b"\x63\x82\x53\x63"
                and dns[16:19] == socket.inet_aton(LAN)[:3]
                and 100 <= dns[19] < 150
            ):
                if b"\x35\x01\x02" in dns[240:]:
                    self.offered = dns[16:20]
                    self.offer.set()
                if b"\x35\x01\x05" in dns[240:] and dns[16:20] == self.offered:
                    self.ip = socket.inet_ntoa(self.offered)
                    self.ack.set()
            if (
                sport == 53
                and dport == 34567
                and dns[:2] == b"\x12\x34"
                and dns[-4:] == self.expected_answer
            ):
                self.answer.set()
            return
        if dport != 53 or len(dns) < 17:
            return
        end = dns.find(b"\0", 12)
        if end == -1 or len(dns) < end + 5:
            return
        question = dns[12 : end + 5]
        name = (
            re.sub(rb"[\x00-\x1f]", b".", question[:-5])
            .lstrip(b".")
            .decode("ascii", "replace")
            .lower()
        )
        good = name.endswith("-audit.example.net") and question[-4:] == b"\0\1\0\1"
        if good:
            self.queries.add(name)
        response = (
            dns[:2]
            + (b"\x81\x80\0\1\0\1" if good else b"\x81\x83\0\1\0\0")
            + b"\0\0\0\0"
            + question
        )
        if good:
            response += bytes.fromhex("c00c000100010000000a0004") + RESULT
        data = ipv4_udp(self.ip, socket.inet_ntoa(pkt[26:30]), 53, sport, response)
        self.send(pkt[6:12] + self.mac + b"\x08\x00" + data)

    def listen(self):
        try:
            with self.listener:
                self.peer, _ = self.listener.accept()
            with self.peer, self.peer.makefile("rb") as stream:
                while header := stream.read(4):
                    size = struct.unpack("!I", header)[0]
                    if size > 65535:
                        return
                    pkt = stream.read(size)
                    if len(pkt) != size:
                        return
                    self.incoming(pkt)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def check_lan(self, name):
        self.answer.clear()
        pkt = (
            self.guest_mac
            + self.mac
            + b"\x08\x00"
            + ipv4_udp(self.ip, LAN, 34567, 53, dns_query(name))
        )
        for _ in range(12):
            self.send(pkt)
            if self.answer.wait(1):
                return
        raise RuntimeError("No DNS answer traversed isolated LAN")

    def check_forwarding(self):
        self.forwarded.clear()
        frame = (
            self.guest_mac
            + self.mac
            + b"\x08\x00"
            + ipv4_udp(self.ip, GATEWAY, 34568, 10080, b"routerupgrade-wan-probe")
        )
        for _ in range(8):
            self.send(frame)
            if self.forwarded.wait(1):
                return
        raise RuntimeError("No forwarded LAN鈫扺AN UDP reply")

    def check_dhcp(self):
        self.offer.clear()
        self.ack.clear()
        discover = bytearray(236)
        discover[0:4] = b"\x01\x01\x06\x00"
        discover[4:8] = b"RUQA"
        discover[10] = 0x80  # Request a broadcast response.
        discover[28:34] = CLIENT_MAC
        discover.extend(b"\x63\x82\x53\x63")

        def exchange(options, event):
            pkt = (
                bytes([255]) * 6
                + CLIENT_MAC
                + b"\x08\x00"
                + ipv4_udp(
                    "0.0.0.0", "255.255.255.255", 68, 67, discover + options + b"\xff"
                )
            )
            for _ in range(5):
                self.send(pkt)
                if event.wait(2):
                    return
            raise RuntimeError("Missing DHCP response in restored LAN subnet")

        exchange(b"\x35\x01\x01", self.offer)
        exchange(
            b"\x35\x01\x03\x32\x04"
            + self.offered
            + b"\x36\x04"
            + socket.inet_aton(LAN),
            self.ack,
        )


def carrier(version, dns_mode):
    rawcore = Path("/fixtures/mihomo")
    if digest(rawcore) != PINNED_MIHOMO:
        raise RuntimeError("Mihomo v1.19.33 public core hash mismatch")
    # Start with the public package defaults to exercise the real OpenClash init.
    uci = Path("/fixtures/uci").read_text()
    replace = {
        "enable": "1",
        "config_path": "/etc/openclash/config/qa.yaml",
        "enable_redirect_dns": "0",
        "redirect_dns": "0",
        "disable_udp_quic": "0",
        "router_self_proxy": "0",
        "operation_mode": dns_mode,
        "en_mode": dns_mode,
        "core_type": "Meta",
    }
    head, sep, later = uci.partition("\nconfig dns_servers")
    for key, value in replace.items():
        head = re.sub(r"(?m)^\s*option " + key + r"\s+[^\n]+$", "", head)
        head += "\n\toption " + key + " '" + value + "'\n"
    uci = head + sep + later
    files = {
        "etc/config/network": f"""config interface 'loopback'
 option device 'lo'
 option proto 'static'
 option ipaddr '127.0.0.1'
 option netmask '255.0.0.0'
config device
 option name 'br-lan'
 option type 'bridge'
 list ports 'eth0'
config interface 'lan'
 option device 'br-lan'
 option proto 'static'
 option ipaddr '{LAN}'
 option netmask '255.255.255.0'
config interface 'wan'
 option device 'eth1'
 option proto 'static'
 option ipaddr '192.0.2.2'
 option netmask '255.255.255.0'
 option gateway '192.0.2.1'
""",
        "etc/config/firewall": """config defaults
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
config zone
 option name 'lan'
 list network 'lan'
 option input 'ACCEPT'
 option output 'ACCEPT'
 option forward 'ACCEPT'
config zone
 option name 'wan'
 list network 'wan'
 option input 'REJECT'
 option output 'ACCEPT'
 option forward 'REJECT'
 option masq '1'
config forwarding
 option src 'lan'
 option dest 'wan'
""",
        "etc/config/dhcp": """config dnsmasq
 option noresolv '1'
 list server '127.0.0.1#5335'
config dhcp 'lan'
 option interface 'lan'
 option start '100'
 option limit '50'
 option leasetime '1h'
config dhcp 'wan'
 option interface 'wan'
 option ignore '1'
""",
        "etc/config/dropbear": "config dropbear\n option Port '2202'\n",
        "etc/config/openclash": uci,
        "etc/openclash/config/qa.yaml": f"""mode: rule
allow-lan: true
log-level: info
proxies: []
proxy-groups:
  - name: AUDIT
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,AUDIT
dns:
  enable: true
  enhanced-mode: {dns_mode}
  listen: 127.0.0.1:7874
  default-nameserver: [192.0.2.1]
  nameserver: [192.0.2.1]
""",
        "etc/AdGuardHome.yaml": """http:
  address: 127.0.0.1:3000
dns:
  bind_hosts: [127.0.0.1]
  port: 5335
  upstream_dns: ["127.0.0.1:7874"]
  use_private_ptr_resolvers: false
filtering:
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
user_rules:
  - "||blocked-audit.example.net^"
schema_version: 34
""",
        "usr/bin/AdGuardHome/data/filters/123.txt": "||fixture.invalid^\n",
        "www/luci-static/argon/background/qa.png": base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNYLfQeAAMYAa0yz5cfAAAAAElFTkSuQmCC"
        ),
    }
    with tarfile.open("synthetic.tgz", "w:gz") as tar:
        for name, text in files.items():
            data = text.encode() if isinstance(text, str) else text
            m = tarfile.TarInfo(name)
            m.mode, m.size = 0o600, len(data)
            tar.addfile(m, io.BytesIO(data))
        tar.add(
            rawcore,
            arcname="etc/openclash/core/clash_meta",
            filter=lambda m: set_mode(m, 0o755),
        )
    dest = Path.cwd() / "private"
    master, slave = os.openpty()
    try:
        args = [
            sys.executable,
            str(APP / "upgrade.py"),
            "prepare",
            "--version",
            version,
            "--backup",
            "synthetic.tgz",
            "--private-dir",
            str(dest),
        ]
        with subprocess.Popen(
            args, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as proc:
            # Approve the local review only for these deliberately synthesized test members.
            os.write(master, b"YES\n")
            output, _ = proc.communicate(timeout=120)
            if proc.returncode:
                raise RuntimeError(
                    "Synthetic backup preparation failed: "
                    + output.decode("utf-8", "replace")[-900:]
                )
    finally:
        os.close(master)
        os.close(slave)
    (src,) = dest.glob("restore-*/*.raw")
    os.rename(src, "carrier.raw")


def set_mode(member, mode):
    member.mode = mode
    return member


class Serial:
    def __init__(self, guest):
        self.guest = guest
        self.buf = b""
        self.poll = selectors.DefaultSelector()
        self.poll.register(guest.stdout, selectors.EVENT_READ)
        self.n = 0

    def wait(self, regex, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if hit := re.search(regex, self.buf):
                out = self.buf[: hit.end()]
                self.buf = self.buf[hit.end() :]
                return hit, out
            if self.poll.select(timeout=1):
                chunk = os.read(self.guest.stdout.fileno(), 32768)
                if not chunk:
                    break
                self.buf = (self.buf + chunk)[-131072:]
        raise RuntimeError("Serial timeout: " + repr(self.buf[-1700:]))

    def login(self):
        self.wait(rb"(?i)activate this console|root@[^#]+#", 160)
        self.guest.stdin.write(b"\r")
        self.wait(rb"root@[^#]+#", 20)

    def cmd(self, cmd, timeout=30):
        self.n += 1
        marker = f"QA{self.n}Z".encode()
        statement = (
            cmd.encode()
            + b"; r=$?; printf '\\nQA%sZ-%d\\n' "
            + str(self.n).encode()
            + b' "$r"\r'
        )
        self.guest.stdin.write(statement)
        hit, out = self.wait(rb"(?m)^[\r]*" + marker + rb"-(\d+)[\r\n]", timeout)
        if int(hit[1]):
            raise RuntimeError(f"{cmd}: {out[-2200:]!r}")
        return out


def isolate_guest_links():
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(8)
        control.connect("qa.qmp")
        with control.makefile("rwb", buffering=0) as stream:
            assert "QMP" in json.loads(stream.readline())
            commands = [{"execute": "qmp_capabilities"}]
            commands += [
                {"execute": "set_link", "arguments": {"name": f"qa{i}", "up": False}}
                for i in (0, 1)
            ]
            for msg in commands:
                stream.write(json.dumps(msg).encode() + b"\r\n")
                while True:
                    reply = json.loads(stream.readline())
                    if "return" in reply:
                        break
                    if "error" in reply:
                        raise RuntimeError(reply["error"])


def boot(boot_number, dns_mode):
    lan, wan = Wire(False), Wire(True)
    args = [
        "qemu-system-x86_64",
        "-no-user-config",
        "-machine",
        "pc,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "2048",
        "-smp",
        "2",
        "-bios",
        "/usr/share/seabios/bios-256k.bin",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-qmp",
        "unix:qa.qmp,server=on,wait=off",
        "-drive",
        "file=system.qa.qcow2,if=none,id=os,format=qcow2",
        "-device",
        "virtio-scsi-pci,id=scsi0",
        "-device",
        "scsi-hd,bus=scsi0.0,scsi-id=0,lun=0,drive=os,bootindex=1",
    ]
    if boot_number == 0:
        args += [
            "-drive",
            "file=carrier.raw,if=none,id=carrier,format=raw,readonly=on",
            "-device",
            "scsi-hd,bus=scsi0.0,scsi-id=1,lun=0,drive=carrier,id=carrier-device",
        ]
    for i, (wire, mac) in enumerate(((lan, LAN_MAC), (wan, WAN_MAC))):
        args += [
            "-netdev",
            f"socket,id=n{i},connect=127.0.0.1:{wire.port}",
            "-device",
            f"virtio-net-pci,id=qa{i},netdev=n{i},mac={mac.hex(':')}",
        ]
    p = subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    s = Serial(p)
    try:
        s.login()
        print(f"Guest {boot_number}: console ready", flush=True)
        s.cmd(
            "ubus -t 80 wait_for network.interface && [ ! -e /tmp/.config_pending ]", 95
        )
        if boot_number == 0:
            s.cmd(
                'd=""; for n in /sys/block/sd?; do [ "$(cat "$n/ro")" = 1 ] && d="/dev/$(basename "$n")"; done; [ -b "$d" ] && [ "$(head -c 10 "$d")" = RESTORE.ID ]'
            )
            s.cmd('tar -xf "$d" -C /tmp RUN.SH')
            s.cmd(
                'for n in $(seq 30); do [ "$(cat /sys/class/net/eth0/carrier)" = 1 ] && break; sleep 1; done; [ "$(cat /sys/class/net/eth0/carrier)" = 1 ]',
                45,
            )
            s.cmd(
                'sh /tmp/RUN.SH "$d" >/tmp/live-link.log 2>&1; [ "$?" != 0 ] && grep -q "live link" /tmp/live-link.log && [ ! -f /etc/openclash/core/clash_meta ]'
            )
            isolate_guest_links()
            s.cmd(
                'for n in $(seq 10); do [ "$(cat /sys/class/net/eth0/carrier)" != 1 ] && break; sleep 1; done; sh /tmp/RUN.SH "$d" >/tmp/restore.log && grep -qx RESTORE_OK /tmp/restore.log',
                120,
            )
            print(
                "PASS: normal restore on delivered disk using verified upstream core",
                flush=True,
            )
        else:
            i = boot_number
            s.cmd(
                '[ ! -b /dev/sdb ] && [ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat /etc/audit-last-boot)" ]'
            )
            s.cmd(
                "test -x /etc/openclash/core/clash_meta && test -s /etc/openclash/config/qa.yaml && test -s /etc/AdGuardHome.yaml"
            )
            s.cmd(
                "for n in $(seq 45); do [ -d /sys/class/net/br-lan/brif/eth0 ] && ip -4 addr show dev eth1 | grep -q 192.0.2.2 && break; sleep 1; done; test -d /sys/class/net/br-lan/brif/eth0 && ip -4 addr show dev eth1 | grep -q 192.0.2.2",
                65,
            )
            s.cmd(
                "for n in $(seq 180); do grep -Fq 'OpenClash Start Successful!' /tmp/openclash.log 2>/dev/null && "
                "pidof dnsmasq >/dev/null && break; sleep 1; done; "
                "grep -Fq 'OpenClash Start Successful!' /tmp/openclash.log && "
                "pidof clash && pidof AdGuardHome && pidof dnsmasq && netstat -lnu | grep ':7874 '",
                230,
            )
            fake = dns_mode == "fake-ip"
            client_name = f"client-b{i}-audit.example.net"
            expected = ANSWER_IP
            if fake:
                result = s.cmd(
                    f"dig +short +time=3 +tries=2 @127.0.0.1 -p 7874 {client_name} A | "
                    "sed 's/^/QA_FAKE_IP=/'"
                )
                match = re.search(rb"(?m)^QA_FAKE_IP=([0-9.]+)\r?$", result)
                if not match or ipaddress.ip_address(
                    match[1].decode()
                ) not in ipaddress.ip_network("198.18.0.0/15"):
                    raise RuntimeError(
                        f"Mihomo did not allocate a fake IPv4 answer: {result[-600:]!r}"
                    )
                expected = match[1].decode()
                lan.expected_answer = socket.inet_aton(expected)
            for port in (7874, 5335, 53):
                name = client_name if fake else f"p{port}-b{i}-audit.example.net"
                lookup = f"dig +time=1 +tries=1 +short @127.0.0.1 -p {port} {name} A | grep -Fxq {expected}"
                s.cmd(
                    f'passed=0; for n in $(seq 15); do if {lookup}; then passed=1; break; fi; sleep 1; done; test "$passed" = 1',
                    50,
                )
                if not fake and name not in wan.queries:
                    raise RuntimeError("WAN query missing for " + name)
            blocked = "blocked-audit.example.net"
            for port in (5335, 53):
                s.cmd(
                    f"dig +noall +comments +time=2 +tries=1 @127.0.0.1 -p {port} {blocked} A "
                    "| grep -Fq 'status: NXDOMAIN'"
                )
            if blocked in wan.queries:
                raise RuntimeError(
                    "The restored ADH user rule allowed a blocked query through"
                )
            lan.check_dhcp()
            lan.check_lan(client_name)
            if not fake and client_name not in wan.queries:
                raise RuntimeError("client query did not reach isolated WAN")
            lan.check_forwarding()
            if wan.forward_source != "192.0.2.2":
                raise RuntimeError(
                    "WAN egress source was not the restored router address"
                )
            s.cmd(
                "test -x /etc/init.d/openclash && /etc/openclash/core/clash_meta -v | grep -Fq 1.19.33"
            )
            s.cmd(
                "ls -ln /etc/AdGuardHome.yaml | grep -q '^-rw-------' && ls -ln /www/luci-static/argon/background/qa.png | grep -q '^-rw-r--r--'"
            )
            s.cmd(
                "wget -qO- http://127.0.0.1/luci-static/argon/background/qa.png | sha256sum | grep -q '^444c26c9af6b4b2f983990a045f17e8469fcd1b968701deb0bc0081416f8e9ce '"
            )
            print(
                f"PASS: boot {i}, {dns_mode}, real OpenClash-managed Mihomo + AGH + dnsmasq, "
                f"LAN DNS {expected}, ADH blocked rule, IPv4 forwarding, DHCP lease {lan.ip}, Argon HTTP",
                flush=True,
            )
        s.cmd("cat /proc/sys/kernel/random/boot_id >/etc/audit-last-boot; sync")
        p.stdin.write(b"poweroff\r")
        p.wait(timeout=80)
    except Exception:
        try:
            print(f"Synthetic WAN observations: {sorted(wan.queries)}", flush=True)
            print(
                s.cmd(
                    "uci -q show dhcp; netstat -lnup | grep -E ':53 |:5335 |:7874 '; dig +time=1 +tries=1 @127.0.0.1 failure-audit.example.net; logread -e dnsmasq | tail -n 16",
                    8,
                ).decode(errors="replace")[-4900:]
            )
            print(
                s.cmd("ip -4 addr; ip route; ifstatus lan; ifstatus wan", 5).decode(
                    errors="replace"
                )[-3900:]
            )
            print(
                s.cmd(
                    "tail -n 24 /tmp/openclash.log; tail -n 6 /tmp/AdGuardHome.log; ps w |grep -E 'clash|GuardHome'|head -10",
                    7,
                ).decode(errors="replace")[-4200:]
            )
        except Exception:
            pass
        raise
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fake-ip", action="store_true")
    fake = parser.parse_args().fake_ip
    dns_mode = "fake-ip" if fake else "redir-host"
    version = os.environ["ROUTER_TEST_RELEASE"]
    before = digest("/firmware.qcow2")
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        carrier(version, dns_mode)
        carrier_before = digest("carrier.raw")
        shutil.copyfile("/firmware.qcow2", "system.qa.qcow2")
        for stage in (0, 1) if fake else (0, 1, 2):
            boot(stage, dns_mode)
        assert (
            digest("/firmware.qcow2") == before
            and digest("carrier.raw") == carrier_before
        )
        os.chdir("/")


if __name__ == "__main__":
    main()
