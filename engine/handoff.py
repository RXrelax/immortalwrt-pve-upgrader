"""Render a portable offline handoff without embedding private file metadata."""
from pathlib import Path
import re
import tempfile

from .layout import DEFAULT_LAYOUT, Layout
from .private_carrier import carrier_marker

_TEMPLATE = Path(__file__).parent / "templates" / "pve-handoff.html"


def write_guide(
    version: str,
    public_dir: Path,
    firmware: dict | None,
    recovery: dict | None,
    layout: Layout = DEFAULT_LAYOUT,
) -> Path:
    """Accept firmware only from the caller's verified build or import result."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("请提供完整的稳定版版本号。")
    marker = carrier_marker(layout)
    for result in (firmware, recovery):
        if result is None:
            continue
        # Older verified results were only produced for the original geometry.
        actual_layout = DEFAULT_LAYOUT
        if "layout" in result:
            dimensions = result["layout"]
            if not isinstance(dimensions, dict) or set(dimensions) != {"disk_gib", "boot_mib"}:
                raise ValueError("产物缺少完整的磁盘布局记录。")
            actual_layout = Layout(**dimensions)
        if actual_layout != layout:
            raise ValueError("产物和手册的磁盘布局不一致。请使用同一布局重新准备。")
    if recovery is not None and ("version" in recovery or "layout" in recovery):
        if recovery.get("version") != version:
            raise ValueError("恢复盘和手册的版本不一致。")
    digest = "尚未验证系统盘。请先在向导内完成公开固件构建或导入经验证的成品。"
    upload_name = "immortalwrt-目标版本-公开SHA前12位.qcow2"
    if firmware is not None:
        if firmware.get("version") != version:
            raise ValueError("固件和手册的版本不一致。")
        value = firmware.get("sha256")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("缺少已验证的系统盘 SHA-256。")
        digest = value.lower()
        upload_name = f"immortalwrt-{version}-{digest[:12]}.qcow2"
    private_status = (
        "已生成私有恢复盘。请在向导结果中单独核对它的 SHA-256。"
        if recovery is not None else "尚未准备私有恢复盘。请先在本机选择备份并通过恢复核对。"
    )

    # Private result values, user-chosen filenames, and paths never enter the HTML.
    page = (_TEMPLATE.read_text(encoding="utf-8")
            .replace("{{VERSION}}", version)
            .replace("{{DISK_GIB}}", str(layout.disk_gib))
            .replace("{{BOOT_MIB}}", str(layout.boot_mib))
            .replace("{{ROOT_MIB}}", f"{layout.root_mib:,}")
            .replace("{{MARKER}}", marker)
            .replace("{{FIRMWARE_DIGEST}}", digest)
            .replace("{{UPLOAD_NAME}}", upload_name)
            .replace("{{PRIVATE_STATUS}}", private_status))
    public_dir = Path(public_dir)
    public_dir.mkdir(parents=True, exist_ok=True)
    output = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", prefix=f"PVE-cutover-{version}-{layout.disk_gib}g-{layout.boot_mib}m-",
        suffix=".html", dir=public_dir, delete=False,
    )
    try:
        with output:
            output.write(page)
    except BaseException:
        Path(output.name).unlink(missing_ok=True)
        raise
    return Path(output.name)
