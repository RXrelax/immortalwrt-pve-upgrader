"""Prepare a version-bound restore carrier locally. Never contacts any server."""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import stat
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Callable
from uuid import uuid4

from . import private_rules as rules
from .layout import DEFAULT_LAYOUT, Layout
from .localpaths import checked_path
from .private_carrier import create_carrier, validate_version


class PrivateError(ValueError):
    """details are intended for a transient local review, never a persistent log."""

    def __init__(self, message: str, details=()):
        super().__init__(message)
        self.details = tuple(details)


def local_path(path: Path, *, output: bool = False) -> Path:
    try:
        path = checked_path(path, allow_missing=output)
    except ValueError as e:
        raise PrivateError(str(e)) from None
    if output:
        sync = {"dropbox", "google drive", "googledrive", "icloud drive", "iclouddrive", "box sync"}
        if any(s.casefold().startswith("onedrive") or s.casefold() in sync for s in path.parts):
            raise PrivateError("请选择本地未启用云同步的私人输出目录。")
        parents = (path, *path.parents)
        if (Path(__file__).resolve().parents[1] in parents
                or any((p / ".git").exists() for p in parents)):
            raise PrivateError("私人输出目录须位于程序目录及 Git 仓库之外。")
    return path


def regular_local(path: Path) -> bool:
    st = path.lstat()
    return stat.S_ISREG(st.st_mode) and not getattr(st, "st_file_attributes", 0) & 0x400


def filter_inputs(entries, folder: Path | None, notices: set[str]):
    """Prefer the archive. An explicit external folder can supplement absent names."""
    archived = {}
    for path, m in entries.items():
        if not path.startswith(rules.FILTERS + "/"):
            continue
        name = path[len(rules.FILTERS) + 1:]
        if "/" in name or not name.lower().endswith(".txt"):
            continue
        if not m.isfile() or m.issparse() or not m.size:
            raise PrivateError("过滤清单中的 .txt 不是非空普通文件，请重新核对备份。")
        for parent in PurePosixPath(path).parents:
            if str(parent) in entries and not entries[str(parent)].isdir():
                raise PrivateError("过滤目录用了链接或异常目录项，请在旧机核对真实目录。")
        archived[name] = m
    supplements = {}
    if folder is not None:
        folder = local_path(folder)
        if not folder.is_dir():
            raise PrivateError("补充过滤文件的位置必须是文件夹。")
        for file in folder.iterdir():
            if not file.name.lower().endswith(".txt") or file.name in archived:
                continue
            if not regular_local(file) or not file.stat().st_size or rules.invalid_text(file.name):
                raise PrivateError("补充目录中的过滤文件必须是非空的本地普通文件。")
            supplements[file.name] = file
        if supplements:
            notices.add(f"从你选择的本地目录补入 {len(supplements)} 项过滤文件；同名文件以备份为准。")
    if not (archived or supplements):
        notices.add("备份没有过滤缓存。若依赖本地规则源或需要离线可用，请取消并指定过滤目录；"
                    "确认无需迁移缓存才继续。AdGuard Home YAML 会保留。")
    return archived, list(supplements.values())


def configured_filter_ids(tar, cfg) -> set[str]:
    """Identify enabled ID-based lists in AdGuard's own emitted block-style YAML."""
    if cfg.size > 4 * 1024**2:
        return set()
    active = False
    wanted: set[str] = set()
    entry: dict[str, str] = {}

    def finish():
        if entry.get("enabled", "true") != "false" and entry.get("id", "").isdigit():
            wanted.add(entry["id"] + ".txt")
        entry.clear()

    with tar.extractfile(cfg) as stream:
        for raw in stream:
            line = raw.decode("utf-8", "surrogateescape").rstrip()
            if not line or line.lstrip().startswith("#"):
                continue
            if re.match(r"^[^\s#-]", line):
                finish()
                active = line in ("filters:", "whitelist_filters:")
                continue
            if not active:
                continue
            item = line.strip()
            if item.startswith("- "):
                finish()
                item = item[2:]
            field = re.fullmatch(r"(enabled|id):\s*(true|false|[0-9]+)(?:\s+#.*)?", item)
            if field:
                entry[field[1]] = field[2]
    finish()
    return wanted


def verify_gzip(path: Path) -> int:
    size = 0
    with gzip.open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            size += len(chunk)
    return size


@contextmanager
def opened_backup(path: Path):
    # Keep a single open regular file for both CRC verification and packing:
    # an export program may replace the selected filename during local review.
    before = path.lstat()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        opened = os.fstat(source.fileno())
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise PrivateError("所选备份正在变化或不是普通文件。请等本地备份写完后重试。")
        with gzip.GzipFile(fileobj=source) as gz:
            while gz.read(1024 * 1024):
                pass
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:gz") as archive:
            yield archive
        after = os.fstat(source.fileno())
        if ((opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                or not os.path.samestat(after, path.lstat())):
            raise PrivateError("备份在准备过程中被更新，已取消输出。请重新选择完成的备份。")


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare_private(
    backup: Path,
    dest_dir: Path,
    version: str,
    filters: Path | None,
    review: Callable[[list[str]], bool],
    log: Callable[[str], None],
    layout: Layout = DEFAULT_LAYOUT,
) -> dict:
    """Return paths for the two private artifacts plus the carrier SHA-256.

    The caller supplies the local review UI. Logs contain totals, not backup
    members, user paths, credentials, subscription names or archive contents.
    The output pair is published by a single directory rename, after checks.
    """
    validate_version(version)
    if not isinstance(layout, Layout):
        raise PrivateError("请选择有效的目标磁盘布局。")
    try:
        backup = local_path(backup)
        if not regular_local(backup):
            raise PrivateError("请选择本地的普通 LuCI/sysupgrade gzip 配置备份。")
        dest = local_path(dest_dir, output=True)
        dest.mkdir(parents=True, mode=0o700, exist_ok=True)
        log("在本机核对备份归档与文件范围。")
        notices: set[str] = set()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid4().hex[:10]
        base = f"restore-{version}-{layout.disk_gib}g-{layout.boot_mib}m-{stamp}"
        final = dest / base
        with tempfile.TemporaryDirectory(prefix=".router-private-", dir=dest) as temp:
            staging = Path(temp) / base
            staging.mkdir(mode=0o700)
            archive = staging / f"{base}.tar.gz"
            raw = staging / f"{base}.raw"
            with opened_backup(backup) as tar:
                entries = rules.inventory(tar)
                archived, additional = filter_inputs(entries, filters, notices)
                filter_names = set(archived) | {f.name for f in additional}
                members = {rules.FILTERS + "/" + n for n in archived}
                selected, links, services = rules.plan(tar, entries, set(), notices, members)
                if "etc/shadow" not in selected:
                    notices.add("备份未包含 /etc/shadow。接入网络前请在本地控制台确认管理员密码，必要时运行 passwd。")
                if not any(sec and sec[0] == "interface" and sec[1:2] != ["loopback"]
                           for sec, _, _ in rules.source_options(tar, selected["etc/config/network"])):
                    notices.add("未识别到回环以外的网络接口配置。请核对这是否是故障前的主路由备份。")
                oc_options = rules.source_options(tar, selected["etc/config/openclash"])
                enabled = [value for sec, opt, value in oc_options
                           if sec == ["openclash", "config"] and opt == "enable"]
                if enabled and enabled[-1].lower() in ("0", "no", "off", "false"):
                    notices.add("备份中 OpenClash 的启用开关已关闭。若预期由它提供 DNS 上游，请先核对备份或在验收时启用服务。")
                missing = configured_filter_ids(tar, selected["etc/AdGuardHome.yaml"]) - filter_names
                if missing:
                    notices.add(f"AdGuard Home 中有 {len(missing)} 项已启用的数字 ID 规则未找到缓存。"
                                "需要离线恢复时请取消并选择补充目录。")
                if notices and not review(sorted(notices)):
                    raise PrivateError("已取消：尚未确认迁移范围。")
                with open(archive, "xb", opener=lambda p, f: os.open(p, f, 0o600)) as output:
                    with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=4) as gz:
                        with tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as out:
                            rules.emit(tar, out, selected, links, services, archived, additional)
            unpacked_bytes = verify_gzip(archive)
            log(f"已核对 {len(filter_names)} 项过滤文件，正在生成只读恢复盘。")
            create_carrier(archive, raw, version, unpacked_bytes, layout)
            digest = file_hash(raw)
            if final.exists():
                raise PrivateError("本次输出名称已存在，请重试。")
            staging.rename(final)
        log("本地配置恢复包与临时盘已生成。")
        return {"raw": final / raw.name, "archive": final / archive.name,
                "sha256": digest, "filter_count": len(filter_names),
                "version": version, "layout": asdict(layout)}
    except rules.LinkIssues as exc:
        raise PrivateError("备份内有需要在本机核对的链接。", exc.details) from None
    except rules.Invalid as exc:
        raise PrivateError(str(exc)) from None
    except (OSError, EOFError, tarfile.TarError) as exc:
        raise PrivateError(f"私人文件读写或完整性检查失败（{type(exc).__name__}）。") from None
