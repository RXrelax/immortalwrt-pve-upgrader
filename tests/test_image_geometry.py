"""Check the selected BIOS disk geometry against an independent MBR fixture."""
from io import BytesIO
import struct
import unittest

from engine.layout import DEFAULT_LAYOUT, Layout
from engine.verify_bios_image import read_ext4, verify


RELEASE_PARTITIONS = ((512, 1_048_576), (1_049_600, 30_406_656))
CUSTOM_PARTITIONS = ((512, 196_608), (197_632, 3_995_648))  # 2 GiB, 96 MiB boot


def partition_table(geometry):
    mbr = bytearray(512)
    mbr[0] = 0xEB
    mbr[-2:] = b"\x55\xaa"
    for index, (start, size) in enumerate(geometry):
        struct.pack_into("<B3xB3xII", mbr, 446 + 16 * index, 0x80 if index == 0 else 0,
                         0x83, start, size)
    return BytesIO(mbr)


class SparseDisk:
    """Stream an MBR and two ext4 superblocks while reusing the same zero buffer."""
    zeros = memoryview(bytes(4 * 1024**2))

    def __init__(self, size, partitions):
        self.size = size
        self.position = 0
        self.data = {0: partition_table(partitions).read()}
        for start, sectors in partitions:
            superblock = bytearray(1024)
            struct.pack_into("<II", superblock, 0, 32, sectors // 2)  # inodes, 1 KiB blocks
            superblock[56:58] = b"\x53\xef"
            struct.pack_into("<I", superblock, 96, 0x40)  # extents
            self.data[start * 512 + 1024] = superblock

    def read(self, count):
        start = self.position
        end = min(start + count, self.size, start + len(self.zeros))
        self.position = end
        block = self.zeros[:end - start]
        for offset, data in self.data.items():
            first, last = max(offset, start), min(offset + len(data), end)
            if first < last:
                block = bytearray(block)
                block[first - start:last - start] = data[first - offset:last - offset]
        return bytes(block) if isinstance(block, bytearray) else block


class LayoutTest(unittest.TestCase):
    def test_release_defaults_and_cache_compatibility(self):
        self.assertEqual(Layout(), DEFAULT_LAYOUT)
        self.assertEqual(DEFAULT_LAYOUT.disk_bytes, 15 * 1024**3)
        self.assertEqual(DEFAULT_LAYOUT.root_mib, 14_847)
        self.assertEqual(DEFAULT_LAYOUT.partitions, RELEASE_PARTITIONS)
        self.assertEqual(DEFAULT_LAYOUT.cache_name("25.12.2"), "firmware-25.12.2")
        with self.assertRaises(AttributeError):
            DEFAULT_LAYOUT.boot_mib = 32

    def test_custom_cache_identity_includes_both_sizes_and_version(self):
        layouts = [DEFAULT_LAYOUT, Layout(8, 256), Layout(8, 512), Layout(16, 256)]
        names = {layout.cache_name(version) for layout in layouts for version in ("25.12.1", "25.12.2")}
        self.assertEqual(len(names), 2 * len(layouts))

    def test_inclusive_layout_limits(self):
        self.assertEqual(Layout(2, 32).root_mib, 2015)
        self.assertEqual(Layout(2, 1535).root_mib, 512)
        self.assertEqual(Layout(128, 4096).root_mib, 126_975)

    def test_invalid_layout_is_rejected(self):
        for disk, boot in [(1, 32), (129, 32), (8, 31), (8, 4097), (2, 1536),
                           (8.0, 64), (8, 64.0), ("8", 64), (8, "64"), (True, 64), (8, False)]:
            with self.subTest(disk=disk, boot=boot), self.assertRaises((ValueError, TypeError)):
                Layout(disk, boot)


class ImageGeometryTest(unittest.TestCase):
    def test_ext4_may_drop_only_a_partial_final_group(self):
        mib = 1024**2
        sb = bytearray(1024)
        struct.pack_into("<I", sb, 0, 32)
        struct.pack_into("<I", sb, 24, 2)  # 4 KiB blocks, 128 MiB groups
        struct.pack_into("<I", sb, 32, 32768)
        sb[56:58] = b"\x53\xef"
        struct.pack_into("<I", sb, 96, 0x40)
        struct.pack_into("<I", sb, 4, 32 * mib // 4096)
        with self.assertRaisesRegex(ValueError, "has not filled"):
            read_ext4(BytesIO(sb), 40 * mib, "boot")
        struct.pack_into("<I", sb, 4, 128 * mib // 4096)
        self.assertEqual(read_ext4(BytesIO(sb), 129 * mib, "boot")["bytes"], 128 * mib)

    def test_stock_32_mib_image_is_rejected_before_reading_filesystems(self):
        with self.assertRaisesRegex(ValueError, "partition 1 has the wrong start or length"):
            verify(partition_table(((512, 65536), (66560, 614400))))

    def test_matching_sizes_with_wrong_root_start_is_rejected(self):
        boot, (root_start, root_size) = RELEASE_PARTITIONS
        with self.assertRaisesRegex(ValueError, "partition 2 has the wrong start or length"):
            verify(partition_table((boot, (root_start + 512, root_size))))

    def test_truncated_disk_is_rejected_with_correct_geometry(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            verify(partition_table(RELEASE_PARTITIONS))

    def test_custom_layout_verifies_both_ext4_sizes_and_whole_disk(self):
        layout = Layout(2, 96)
        self.assertEqual(layout.partitions, CUSTOM_PARTITIONS)
        size = 2 * 1024**3
        result = verify(SparseDisk(size, CUSTOM_PARTITIONS), layout)
        self.assertEqual(result["image_bytes"], size)
        self.assertEqual(result["partition_table"], "MBR")
        self.assertEqual([(p["start"], p["bytes"], p["ext4"]["bytes"]) for p in result["partitions"]],
                         [(s * 512, n * 512, n * 512) for s, n in CUSTOM_PARTITIONS])

    def test_custom_disk_requires_matching_selected_layout(self):
        for layout in [DEFAULT_LAYOUT, Layout(2, 95), Layout(3, 96)]:
            with self.subTest(layout=layout), self.assertRaisesRegex(ValueError, "wrong start or length"):
                verify(partition_table(CUSTOM_PARTITIONS), layout)

    def test_custom_layout_checks_last_byte(self):
        for delta, error in [(-1, "truncated"), (1, "exceeds expected disk size")]:
            with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, error):
                verify(SparseDisk(2 * 1024**3 + delta, CUSTOM_PARTITIONS), Layout(2, 96))
