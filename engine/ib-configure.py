"""Configure an authenticated, unpacked ImmortalWrt x86/64 ImageBuilder."""
import argparse
import re
import sys
from pathlib import Path

from layout import Layout, add_layout_arguments


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f"Unsupported ImageBuilder recipe near: {old[:90]}")
    return text.replace(old, new)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("version")
parser.add_argument("manager", choices=("apk", "opkg"))
add_layout_arguments(parser)
args = parser.parse_args()
try:
    layout = Layout(args.disk_gib, args.boot_mib)
except ValueError as exc:
    parser.error(str(exc))
version, manager = args.version, args.manager
print(f"Release {version}, package manager {manager}, layout BIOS ext4 "
      f"{layout.boot_mib}+{layout.root_mib} MiB on {layout.disk_gib} GiB")
repos = Path("repositories" if manager == "apk" else "repositories.conf").read_text()
urls = re.findall(r"https?://[^\s]+", repos)
prefix = f"https://downloads.immortalwrt.org/releases/{version}/"
if not urls or any(not url.startswith(prefix) for url in urls):
    sys.exit("Unexpected release or non-official feed in ImageBuilder")
if manager == "opkg" and not re.search(r"(?m)^\s*option\s+check_signature\s*$", repos):
    sys.exit("Package signatures are disabled")
config = Path(".config")
text = config.read_text()
settings = {
    "TARGET_ROOTFS_TARGZ": "n", "TARGET_ROOTFS_SQUASHFS": "n",
    "GRUB_EFI_IMAGES": "n", "ISO_IMAGES": "n", "QCOW2_IMAGES": "n",
    "VDI_IMAGES": "n", "VMDK_IMAGES": "n", "VHDX_IMAGES": "n",
    "TARGET_ROOTFS_EXT4FS": "y", "TARGET_IMAGES_GZIP": "y", "GRUB_IMAGES": "y",
    "TARGET_KERNEL_PARTSIZE": str(layout.boot_mib), "TARGET_ROOTFS_PARTSIZE": str(layout.root_mib),
}
for key, value in settings.items():
    key = "CONFIG_" + key
    line = f"# {key} is not set" if value == "n" else f"{key}={value}"
    text, count = re.subn(rf"^(?:{key}=.*|# {key} is not set)$", line, text, flags=re.MULTILINE)
    if count != 1:
        sys.exit(f"Unsupported ImageBuilder config: {key}")
config.write_text(text)

recipe = Path("target/linux/x86/image/Makefile")
recipe.write_text(replace_once(recipe.read_text(), "IMAGES-y := rootfs.img.gz", "IMAGES-y :="))
writer = Path("scripts/gen_image_generic.sh")
text = writer.read_text()
# Preserve ptgen's signed release geometry. A new output is zero-filled by
# truncate; sparse writes avoid allocating and transferring empty blocks.
changes = {
    '[ -n "$PADDING" ] && dd if=/dev/zero of="$OUTPUT" bs=512 seek="$ROOTFSOFFSET" conv=notrunc count="$ROOTFSSIZE"':
        'bash /engine/check-ext4.sh "$ROOTFSIMAGE"\n[ -n "$PADDING" ] && truncate -s "$(((ROOTFSOFFSET + ROOTFSSIZE) * 512))" "$OUTPUT"',
    'dd if="$ROOTFSIMAGE" of="$OUTPUT" bs=512 seek="$ROOTFSOFFSET" conv=notrunc':
        'dd if="$ROOTFSIMAGE" of="$OUTPUT" bs=4M oflag=seek_bytes seek="$((ROOTFSOFFSET * 512))" conv=notrunc,sparse',
    'dd if="$OUTPUT.kernel" of="$OUTPUT" bs=512 seek="$KERNELOFFSET" conv=notrunc':
        'bash /engine/check-ext4.sh "$OUTPUT.kernel"\ndd if="$OUTPUT.kernel" of="$OUTPUT" bs=4M oflag=seek_bytes seek="$((KERNELOFFSET * 512))" conv=notrunc,sparse',
}
for old, new in changes.items():
    text = replace_once(text, old, new)
writer.write_text(text)

makefile = Path("Makefile")
text = makefile.read_text()
hook = "\t$(call prepare_rootfs,$(TARGET_DIR),$(USER_FILES),$(DISABLED_SERVICES))"
text = replace_once(text, hook, '\t@python3 /engine/ib-hotplug.py "$(TARGET_DIR)"\n' + hook)
# 25.12 FormatPackages keeps pkg_ver from the previous entry when that entry
# has an explicit version. Reset it before unversioned package constraints.
if manager == "apk":
    old = "$(if $(findstring =,$(pkg)),$(eval pkg_ver:==$(lastword $(subst =, ,$(pkg)))))"
    text = text.replace(old, old[:-1] + ",$(eval pkg_ver:=))")
makefile.write_text(text)
