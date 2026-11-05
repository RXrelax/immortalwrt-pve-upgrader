"""Read-only geometry and filesystem checks for the requested BIOS image."""

import argparse
import gzip
import json
import struct
import sys
import uuid
import zlib

if __package__:
    from .layout import DEFAULT_LAYOUT, Layout, MIB, SECTOR, add_layout_arguments
else:  # Executed as a standalone script inside the Linux tool container.
    from layout import DEFAULT_LAYOUT, Layout, MIB, SECTOR, add_layout_arguments

# Keep defaults available to callers that inspect the bundled release profile.
DISK_BYTES = DEFAULT_LAYOUT.disk_bytes
BOOT_BYTES = DEFAULT_LAYOUT.boot_mib * MIB
BIOS_PARTITIONS = DEFAULT_LAYOUT.partitions


def require(ok, message):
    if not ok:
        raise ValueError(message)


def advance(stream, count):
    while count:
        chunk = stream.read(min(count, 4 * MIB))
        require(chunk, "image is truncated")
        count -= len(chunk)


def read_ext4(stream, partition_size, name):
    sb = stream.read(1024)
    require(len(sb) == 1024, f"{name}: truncated superblock")
    require(sb[56:58] == b"\x53\xef", f"{name}: invalid ext magic")
    incompat = struct.unpack_from("<I", sb, 96)[0]
    require(incompat & (0x40 | 0x80 | 0x200), f"{name}: no ext4-specific feature")
    log_block_size = struct.unpack_from("<I", sb, 24)[0]
    require(log_block_size <= 6, f"{name}: invalid block size")
    block_size = 1024 << log_block_size
    blocks = struct.unpack_from("<I", sb, 4)[0]
    if incompat & 0x80:
        blocks |= struct.unpack_from("<I", sb, 336)[0] << 32
    fs_bytes = blocks * block_size
    require(0 < fs_bytes <= partition_size, f"{name}: filesystem does not fit partition")
    # make_ext4fs may drop a final group too small for its metadata. The
    # filesystem then ends on a group boundary. A stock 32 MiB filesystem
    # inside a slightly larger custom boot partition must still be rejected.
    if fs_bytes != partition_size:
        group_blocks = struct.unpack_from("<I", sb, 32)[0]
        require(group_blocks and blocks % group_blocks == 0 and
                partition_size - fs_bytes < group_blocks * block_size and
                partition_size - fs_bytes <= 16 * MIB, f"{name}: filesystem has not filled its partition")
    inodes = struct.unpack_from("<I", sb, 0)[0]
    require(inodes >= 2, f"{name}: invalid inode count")
    return {"bytes": fs_bytes, "block_bytes": block_size, "uuid": str(uuid.UUID(bytes=sb[104:120]))}


def verify(stream, layout=DEFAULT_LAYOUT):
    mbr = stream.read(SECTOR)
    require(mbr[510:] == b"\x55\xaa", "invalid BIOS MBR signature")
    require(any(mbr[:440]), "BIOS bootstrap area is empty")
    partitions = []
    previous_end = SECTOR
    for slot in range(4):
        entry = mbr[446 + slot * 16 : 462 + slot * 16]
        if slot >= 2:
            require(not any(entry), "unexpected third or fourth MBR partition")
            continue
        flag, kind, start_lba, sectors = struct.unpack("<B3xB3xII", entry)
        require(flag == (0x80 if slot == 0 else 0), "unexpected active partition flag")
        require(kind == 0x83, f"partition {slot + 1} is not MBR Linux type 0x83")
        require((start_lba, sectors) == layout.partitions[slot],
                f"partition {slot + 1} has the wrong start or length: {start_lba}/{sectors} sectors")
        start, size = start_lba * SECTOR, sectors * SECTOR
        require(start >= previous_end and size >= 2048, "overlapping or empty partition")
        previous_end = start + size
        require(previous_end <= layout.disk_bytes, "partition extends beyond expected disk size")
        partitions.append({"start": start, "bytes": size})

    position = len(mbr)
    for part, name in zip(partitions, ("boot", "root")):
        offset = part["start"] + 1024
        advance(stream, offset - position)
        part["ext4"] = read_ext4(stream, part["bytes"], name)
        position = offset + 1024
    advance(stream, layout.disk_bytes - position)
    # This final read also verifies the gzip trailer, including CRC, before success.
    require(not stream.read(1), "image exceeds expected disk size")
    return {"image_bytes": layout.disk_bytes, "partition_table": "MBR", "partitions": partitions,
            "layout": {"disk_gib": layout.disk_gib, "boot_mib": layout.boot_mib}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="raw image or gzip-compressed image")
    add_layout_arguments(parser)
    args = parser.parse_args()
    try:
        layout = Layout(args.disk_gib, args.boot_mib)
        with open(args.image, "rb") as raw:
            if raw.peek(2)[:2] == b"\x1f\x8b":
                with gzip.GzipFile(fileobj=raw, mode="rb") as stream:
                    result = verify(stream, layout)
            else:
                result = verify(raw, layout)
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
