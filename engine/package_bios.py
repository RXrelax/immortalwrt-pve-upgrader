#!/usr/bin/env python3
"""Check a local ImageBuilder BIOS product and produce a PVE QCOW2 on Linux."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

if __package__:
    from .layout import Layout, MIB, add_layout_arguments
    from .verify_bios_image import require, verify
else:
    from layout import Layout, MIB, add_layout_arguments
    from verify_bios_image import require, verify


ZERO = bytes(MIB)


def sparse_write(out, chunk):
    if chunk == ZERO[:len(chunk)]:
        out.seek(len(chunk), os.SEEK_CUR)
    else:
        out.write(chunk)


def unpack_first_member(source, raw, limit):
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    pending = b""
    with source.open("rb") as src, raw.open("xb") as out:
        while not decoder.eof:
            if not pending:
                pending = src.read(64 * 1024)
                require(pending, "truncated gzip member")
            chunk = decoder.decompress(pending, len(ZERO))
            pending = decoder.unconsumed_tail
            require(out.tell() + len(chunk) <= limit, "source member exceeds target capacity")
            sparse_write(out, chunk)
        member_size = out.tell()
        footer_size = os.fstat(src.fileno()).st_size - src.tell() + len(decoder.unused_data)
        out.truncate(limit)
    return member_size, footer_size


def check_footer(fwtool, source):
    types = []
    for flag, name in (("-i", "metadata"), ("-s", "signature")):
        command = [fwtool, flag, os.devnull, source]
        if subprocess.run(command, capture_output=True).returncode == 0:
            types.append(name)
    require(types, "data after gzip is not a readable fwtool metadata/signature trailer")
    return types


def slice_partition(raw, part, image):
    with raw.open("rb") as src, image.open("xb") as out:
        src.seek(part["start"])
        remain = part["bytes"]
        while remain:
            chunk = src.read(min(len(ZERO), remain))
            require(chunk, "partition extends beyond source")
            sparse_write(out, chunk)
            remain -= len(chunk)
        out.truncate(part["bytes"])


def debug(image, command, **kwargs):
    return subprocess.run(
        ["debugfs", "-R", command, image], check=True, stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"}, **kwargs
    )


def stat(image, path, kind="regular", executable=False):
    result = debug(image, "stat " + path, stdout=subprocess.PIPE, text=True)
    entry = re.search(r"\bType:\s+(\w+)\s+Mode:\s+([0-7]+)", result.stdout)
    require(entry and entry[1] == kind, f"{path}: missing or unexpected inode type")
    if executable:
        require(int(entry[2], 8) & 0o111, f"{path}: not executable")
    return result.stdout


def read_text(image, path):
    stat(image, path)
    return debug(image, "cat " + path, stdout=subprocess.PIPE, text=True).stdout


def read_public_binary(image, path, cache):
    stat(image, path)
    with cache.open("wb") as out:
        debug(image, "cat " + path, stdout=out)
    require(cache.stat().st_size > 0, f"{path}: file is empty")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def adh_release_digest(archive):
    with tarfile.open(archive, "r:gz") as tar:
        entries = [m for m in tar if m.name.removeprefix("./") == "AdGuardHome/AdGuardHome"]
        require(len(entries) == 1 and entries[0].isfile() and entries[0].size > 0,
                "official AdGuardHome archive is missing the native executable")
        digest = hashlib.sha256()
        with tar.extractfile(entries[0]) as source:
            for chunk in iter(lambda: source.read(MIB), b""):
                digest.update(chunk)
        return digest.hexdigest()


def check_filesystems(raw, geometry, directory, expected_adh, version):
    boot, root = directory / "boot.ext4", directory / "root.ext4"
    for image, partition in zip((boot, root), geometry["partitions"]):
        slice_partition(raw, partition, image)
        # Keep the complete fsck transcript on stderr so stdout remains the JSON report.
        check = subprocess.run(["e2fsck", "-fn", image], stdin=subprocess.DEVNULL,
                               stdout=sys.stderr, env={**os.environ, "LC_ALL": "C"})
        if check.returncode:
            reason = "uncorrected filesystem errors" if check.returncode > 0 and check.returncode & 4 else "check did not finish cleanly"
            raise ValueError(f"{image.name}: e2fsck -fn returned {check.returncode} ({reason})")
        partition["e2fsck_read_only_exit"] = check.returncode
    with raw.open("rb") as disk:
        disk.seek(440)
        signature = int.from_bytes(disk.read(4), "little")
    cfg = read_text(boot, "/boot/grub/grub.cfg")
    partuuid = f"{signature:08x}-02"
    require("(hd0,msdos1)" in cfg and
            re.search(r"^\s*linux\s+/boot/vmlinuz\s+.*\broot=PARTUUID=" + partuuid + r"\b", cfg, re.M | re.I),
            "BIOS GRUB kernel/root reference does not match the MBR disk signature")
    cache = directory / "public-binary"
    read_public_binary(boot, "/boot/grub/core.img", cache)
    read_public_binary(boot, "/boot/vmlinuz", cache)
    with cache.open("rb") as kernel:
        header = kernel.read(0x238)
    require(len(header) == 0x238 and header[510:512] == b"\x55\xaa" and
            header[514:518] == b"HdrS" and header[0x236] & 1, "kernel is not a 64-bit x86 bzImage")

    release = read_text(root, "/etc/openwrt_release")
    for key, expected in (("DISTRIB_ID", "ImmortalWrt"), ("DISTRIB_RELEASE", version), ("DISTRIB_TARGET", "x86/64")):
        require(re.search(rf"^{key}=['\"]?{re.escape(expected)}['\"]?$", release, re.M), f"unexpected {key}")
    core = "/usr/bin/AdGuardHome/AdGuardHome"
    stat(root, core, executable=True)
    read_public_binary(root, core, cache)
    with cache.open("rb") as binary:
        elf = binary.read(20)
    require(len(elf) == 20 and elf[:6] == b"\x7fELF\x02\x01" and
            struct.unpack_from("<H", elf, 18)[0] == 62, "AdGuardHome is not x86-64 ELF")
    digest = file_sha256(cache)
    require(digest == expected_adh, "AdGuardHome differs from the verified upstream release archive")
    init = "/etc/init.d/AdGuardHome"
    stat(root, init, executable=True)
    service = read_text(root, init)
    for token in ("USE_PROCD=1", core, "-c /etc/AdGuardHome.yaml", "-w /usr/bin/AdGuardHome"):
        require(token in service, f"AdGuardHome init script missing {token}")
    for name in ("S95AdGuardHome", "K01AdGuardHome"):
        link = stat(root, "/etc/rc.d/" + name, "symlink")
        target = re.search(r'Fast link dest:\s*"([^"]+)"', link)
        require(target and posixpath.normpath(posixpath.join("/etc/rc.d", target[1])) == init,
                f"{name}: wrong service symlink destination")
    keep = read_text(root, "/lib/upgrade/keep.d/adguardhome-native").splitlines()
    for path in ("/etc/AdGuardHome.yaml", core.rsplit("/", 1)[0] + "/data/filters/"):
        require(path in keep, f"AdGuardHome keep.d missing {path}")
    stat(root, "/etc/init.d/openclash", executable=True)
    return {"kernel": "x86-64 bzImage", "grub_root_partuuid": partuuid,
            "release": f"ImmortalWrt {version} x86/64", "adguardhome_sha256": digest,
            "adguardhome_init_links": ["S95AdGuardHome", "K01AdGuardHome"],
            "adguardhome_keep_checked": True, "openclash_init_present": True}


def package(args):
    layout = Layout(args.disk_gib, args.boot_mib)
    for tool in ("qemu-img", "debugfs", "e2fsck"):
        require(shutil.which(tool), f"missing {tool}")
    require(args.source.is_file() and args.adh_archive.is_file(), "missing source image or AdGuardHome release archive")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version), "expected a stable release")
    manifest = args.manifest.read_text(encoding="utf-8")
    openclash = re.findall(r"^luci-app-openclash(?:\s+-\s+|[ \t]+|-(?=[v0-9]))(\S+)$", manifest, re.M)
    require(len(openclash) == 1, "package manifest does not identify a unique OpenClash version")
    expected_adh = adh_release_digest(args.adh_archive)
    require(not args.output.exists(), "output already exists")
    with tempfile.TemporaryDirectory(prefix="pve-bios-", dir=args.work_dir) as tmp:
        directory = Path(tmp)
        raw = directory / "disk.raw"
        member, footer = unpack_first_member(args.source, raw, layout.disk_bytes)
        trailers = check_footer(args.fwtool, args.source) if footer else []
        with raw.open("rb") as disk:
            geometry = verify(disk, layout)
        root = geometry["partitions"][1]
        require(member >= root["start"] + root["bytes"], "source gzip member ends inside root partition")
        summary = check_filesystems(raw, geometry, directory, expected_adh, args.version)
        # Reserve the destination exclusively; clear only this run's output on failure.
        with args.output.open("xb"):
            pass
        try:
            subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", raw, args.output], check=True)
            info = json.loads(subprocess.check_output(["qemu-img", "info", "--output=json", args.output]))
            require(info["format"] == "qcow2" and info["virtual-size"] == layout.disk_bytes and
                    not info.get("backing-filename"), "unexpected QCOW2 geometry or backing image")
            subprocess.run(["qemu-img", "check", "-q", "-f", "qcow2", args.output], check=True)
            subprocess.run(["qemu-img", "compare", "-q", "-f", "raw", "-F", "qcow2", raw, args.output], check=True)
        except BaseException:
            args.output.unlink()
            raise
    return {**geometry, **summary, "gzip_payload_bytes": member, "tail_padding_added": layout.disk_bytes - member,
            "fwtool_trailer_bytes": footer, "fwtool_chunks_read": trailers,
            "qcow2_check": "passed", "qcow2_raw_compare": "identical", "output": args.output.name,
            "sha256": file_sha256(args.output), "source_sha256": file_sha256(args.source),
            "manifest_sha256": file_sha256(args.manifest), "openclash_version": openclash[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="original local BIOS combined.img.gz")
    parser.add_argument("output", type=Path, help="new QCOW2 file (must not already exist)")
    parser.add_argument("--adh-archive", type=Path, required=True, help="verified upstream AdGuardHome Linux AMD64 release archive")
    parser.add_argument("--version", required=True, help="expected ImmortalWrt stable version")
    parser.add_argument("--manifest", type=Path, required=True, help="package manifest from the same image build")
    parser.add_argument("--fwtool", default="fwtool", help="ImageBuilder host fwtool, needed only for firmware trailers")
    parser.add_argument("--work-dir", type=Path, help="scratch parent on native Linux filesystem")
    add_layout_arguments(parser)
    args = parser.parse_args()
    try:
        print(json.dumps(package(args), indent=2))
    except (OSError, ValueError, EOFError, tarfile.TarError, subprocess.CalledProcessError, zlib.error) as exc:
        print(f"packaging failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
