"""Requested BIOS/MBR geometry shared by the host, builder, and guest verifier."""
from dataclasses import dataclass


MIB = 1024 ** 2
SECTOR = 512


@dataclass(frozen=True)
class Layout:
    disk_gib: int = 15
    boot_mib: int = 512

    def __post_init__(self):
        if type(self.disk_gib) is not int or not 2 <= self.disk_gib <= 128:
            raise ValueError("系统盘容量须为 2 至 128 之间的整数（GiB）。")
        if type(self.boot_mib) is not int or not 32 <= self.boot_mib <= 4096:
            raise ValueError("启动分区容量须为 32 至 4096 之间的整数（MiB）。")
        if self.root_mib < 512:
            raise ValueError("所选布局的根分区小于 512 MiB。请增大系统盘或减小启动分区。")

    @property
    def root_mib(self):
        return self.disk_gib * 1024 - self.boot_mib - 1

    @property
    def disk_bytes(self):
        return self.disk_gib * 1024 * MIB

    @property
    def partitions(self):
        # The x86 ImageBuilder calls ptgen with 256 KiB alignment. It inserts
        # a 256 KiB gap before each partition, with 512 KiB left at disk end.
        sectors_per_mib = MIB // SECTOR
        gap = sectors_per_mib // 4
        boot = self.boot_mib * sectors_per_mib
        return ((gap, boot), (2 * gap + boot, self.root_mib * sectors_per_mib))

    def cache_name(self, version):
        name = f"firmware-{version}"
        if self == DEFAULT_LAYOUT:
            return name
        return f"{name}-{self.disk_gib}g-{self.boot_mib}m"


DEFAULT_LAYOUT = Layout()


def add_layout_arguments(parser):
    parser.add_argument("--disk-gib", type=int, default=DEFAULT_LAYOUT.disk_gib,
                        help="系统盘容量（GiB）")
    parser.add_argument("--boot-mib", type=int, default=DEFAULT_LAYOUT.boot_mib,
                        help="启动分区容量（MiB）")
