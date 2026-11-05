"""Validate a completed public release before reuse, import, or presentation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
from zipfile import ZipFile

from .layout import DEFAULT_LAYOUT, SECTOR, Layout
from .localpaths import checked_path


ROOT = Path(__file__).resolve().parent
FILES = ("router.qcow2", "router.sha256", "router.manifest", "verification.json")


def release_number(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{2}\.[0-9]{1,2}\.[0-9]{1,3}", value):
        raise ValueError("请输入正式版本号，例如 25.12.2。")
    return value


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(2**20), b""):
            h.update(block)
    return h.hexdigest()


def layout_fields(layout):
    return {"disk_gib": layout.disk_gib, "boot_mib": layout.boot_mib}


def report_matches_layout(data, layout):
    if "layout" not in data:
        # The original release predates this field. Its geometry is still checked below.
        return layout == DEFAULT_LAYOUT
    fields = data["layout"]
    return (isinstance(fields, dict) and all(type(v) is int for v in fields.values())
            and fields == layout_fields(layout))


def check(directory, version, layout=DEFAULT_LAYOUT):
    release_number(version)
    directory = checked_path(directory)
    disk, checksum, manifest, report = [checked_path(directory / n) for n in FILES]
    if not all(p.is_file() and not p.is_symlink() for p in (disk, checksum, manifest, report)):
        raise ValueError("成品不完整；请选择新的公开输出目录或重新导入验证包。")
    if report.stat().st_size > 2**20 or checksum.stat().st_size > 1024 or manifest.stat().st_size > 8 * 2**20:
        raise ValueError("公开成品的报告、摘要或软件包清单大小异常。")
    report_bytes = report.read_bytes()
    data = json.loads(report_bytes.decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("成品验证报告格式有误。")
    with disk.open("rb") as f:
        header = f.read(104)
    if (len(header) != 104 or header[:4] != b"QFI\xfb" or
            struct.unpack_from(">I", header, 4)[0] != 3 or header[8:20] != bytes(12) or
            struct.unpack_from(">Q", header, 24)[0] != layout.disk_bytes or header[72:80] != bytes(8)):
        raise ValueError(f"系统盘与预期的独立 {layout.disk_gib} GiB QCOW2 不符。")
    parts = data.get("partitions", [])
    expected_parts = [(start * SECTOR, length * SECTOR) for start, length in layout.partitions]
    if not (data.get("release") == f"ImmortalWrt {version} x86/64" and report_matches_layout(data, layout)
            and data.get("image_bytes") == layout.disk_bytes and data.get("partition_table") == "MBR"
            and isinstance(parts, list) and len(parts) == 2 and all(isinstance(p, dict) for p in parts)
            and [(p.get("start"), p.get("bytes")) for p in parts] == expected_parts
            and all(p.get("e2fsck_read_only_exit") == 0 for p in parts)
            and data.get("qcow2_check") == "passed" and data.get("qcow2_raw_compare") == "identical"
            and data.get("boot_verified") is True and data.get("openclash_version")
            and data.get("adguardhome_keep_checked") is True):
        raise ValueError("版本、分区结构、文件系统或冷启动验证记录不匹配，停止使用此成品。")
    expected = checksum.read_text("ascii").strip().split()
    h = digest(disk)
    if expected != [h, "router.qcow2"] or h != data.get("sha256") or digest(manifest) != data.get("manifest_sha256"):
        raise ValueError("成品或软件清单的 SHA-256 不匹配。")
    return dict(version=version, layout=layout_fields(layout), qcow2=disk, verification=report,
                manifest=manifest, sha256=h, report_sha256=hashlib.sha256(report_bytes).hexdigest())


def release_pins():
    return json.loads((ROOT / "published-bundles.json").read_text("utf-8"))


def receipt_path(result):
    base = (os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") if os.name == "nt" else (
        os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    directory = Path(base) / "RouterUpgrade" / "verified-builds"
    layout = Layout(**result["layout"])
    if layout != DEFAULT_LAYOUT:
        directory = directory / layout.cache_name(result["version"])
    return checked_path(directory / result["report_sha256"], allow_missing=True)


def receipt_text(result):
    fields = result["layout"]
    return f'{result["version"]} {fields["disk_gib"]} {fields["boot_mib"]} {result["sha256"]}'


def remember_boot_test(result):
    """The public cache cannot vouch for itself. Save a receipt only after our own boot test."""
    receipt = receipt_path(result)
    receipt.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = (receipt_text(result) + "\n").encode("ascii")
    with tempfile.NamedTemporaryFile(dir=receipt.parent, delete=False) as out:
        name = Path(out.name)
        try:
            out.write(content)
        except BaseException:
            out.close()
            name.unlink(missing_ok=True)
            raise
    try:
        name.replace(receipt)
    finally:
        name.unlink(missing_ok=True)


def load_verified_firmware(version, public_dir, log=print, *, layout=DEFAULT_LAYOUT):
    dest = checked_path(Path(public_dir) / layout.cache_name(release_number(version)), allow_missing=True)
    if not dest.exists():
        return None
    log("正在重新校验本地系统盘和软件清单…")
    result = check(dest, version, layout)
    if layout == DEFAULT_LAYOUT and any(
            pin["version"] == version and report_matches_layout(pin, layout)
            and pin["report_sha256"] == result["report_sha256"] for pin in release_pins().values()):
        return result
    receipt = receipt_path(result)
    if receipt.is_file() and receipt.stat().st_size < 256:
        text = receipt.read_text("ascii").strip()
        if text == receipt_text(result) or (layout == DEFAULT_LAYOUT and text == version + " " + result["sha256"]):
            return result
    raise ValueError("此缓存缺少匹配的发布记录或本机冷启动记录。请用新公开目录导入随附成品或重新构建。")


def import_firmware_bundle(bundle_path, public_dir, log=print, *, layout=DEFAULT_LAYOUT):
    """Accept only complete release ZIPs pinned with this version of the app."""
    if layout != DEFAULT_LAYOUT:
        raise ValueError("公开发行 ZIP 仅适用于默认分区布局。请在本机构建所选布局。")
    root = checked_path(public_dir, allow_missing=True)
    root.mkdir(parents=True, exist_ok=True)
    pins = release_pins()
    bundle_path = checked_path(bundle_path)
    log("正在比对公开发布包的完整 SHA-256…")
    with bundle_path.open("rb") as source:
        h = hashlib.sha256()
        for block in iter(lambda: source.read(2**20), b""):
            h.update(block)
        pin = pins.get(h.hexdigest())
        if not pin or not report_matches_layout(pin, layout):
            raise ValueError("此 ZIP 不在本版程序的公开发布校验表中。请使用对应发布包或自行构建。")
        version = release_number(pin["version"])
        cached = load_verified_firmware(version, root, log)
        if cached:
            if cached["report_sha256"] != pin["report_sha256"]:
                raise ValueError("所选 ZIP 与缓存中的同版本系统盘来自不同构建。请选用新的公开输出目录。")
            return cached
        source.seek(0)
        target = root / layout.cache_name(version)
        with tempfile.TemporaryDirectory(dir=root, prefix=".import-") as working:
            stage = Path(working) / "checked"
            stage.mkdir()
            with ZipFile(source) as z:
                if sorted(z.namelist()) != sorted(FILES):
                    raise ValueError("公开成品 ZIP 的文件清单不匹配。")
                for name in FILES:
                    with z.open(name) as src, (stage / name).open("xb") as dst:
                        shutil.copyfileobj(src, dst, 2**20)
            if check(stage, version)["report_sha256"] != pin["report_sha256"]:
                raise ValueError("公开 ZIP 的内部报告与发布记录不匹配。")
            try:
                stage.rename(target)
            except OSError:
                # Another import may have completed while we verified the exact same file.
                if not target.is_dir() or check(target, version)["report_sha256"] != pin["report_sha256"]:
                    raise
    return check(target, version)
