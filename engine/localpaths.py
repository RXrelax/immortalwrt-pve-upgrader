"""Reject remote and redirected paths before opening selected migration files."""
import os
from pathlib import Path
import re
import stat


def checked_path(value, *, allow_missing=False):
    value = os.fspath(value)
    spelling = value.replace("\\", "/")
    if not value or spelling.startswith(("//", "/??/", "/Device/")) or re.match(
            r"^[a-z][a-z0-9+.-]*:/", spelling, re.I) and not re.match(r"^[a-z]:/", spelling, re.I):
        raise ValueError("请选择本机磁盘上的路径；不能使用网络共享或下载地址。")
    path = Path(os.path.abspath(os.path.expanduser(value)))
    if os.name == "nt":
        import ctypes
        if (path.drive.startswith("\\\\") or not re.fullmatch("[a-zA-Z]:", path.drive)
                or ctypes.windll.kernel32.GetDriveTypeW(path.anchor) not in (2, 3, 5, 6)):
            raise ValueError("请选择本机磁盘；不能使用映射网络盘或设备路径。")
        if any(":" in part for part in path.parts[1:]):
            raise ValueError("请选择普通文件或目录。")
    # Resolving first could traverse a junction pointing to an SMB share.
    # Inspect each component without dereferencing it, starting at the volume.
    for component in [*reversed(path.parents), path]:
        try:
            meta = component.lstat()
        except FileNotFoundError:
            if allow_missing:
                break
            raise
        if stat.S_ISLNK(meta.st_mode) or getattr(meta, "st_file_attributes", 0) & 0x400:
            raise ValueError("选中的路径经过链接或重解析点，请选择文件的真实本地路径。")
    return path
