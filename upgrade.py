"""RouterUpgrade public API and scriptable CLI. Run python upgrade.py --help."""
import argparse
from pathlib import Path
import sys

from engine.artifacts import import_firmware_bundle, load_verified_firmware, release_number
from engine.dockerbuild import build_firmware as build_local
from engine.handoff import write_guide
from engine.layout import DEFAULT_LAYOUT, Layout, add_layout_arguments
from engine.private_restore import prepare_private
from engine.releases import discover, official_layout
from engine.localpaths import checked_path


def discover_latest(log=print):
    return discover(log)


def prepare_restore(version, backup, private_dir, filters=None, review=None, log=print, layout=DEFAULT_LAYOUT):
    supported(version)
    if not callable(review):
        raise ValueError("必须由操作者在本机确认需要复核的配置。")
    return prepare_private(Path(backup), Path(private_dir), release_number(version),
                           Path(filters) if filters else None, review, log, layout=layout)


def build_firmware(version, public_dir, log=print, layout=DEFAULT_LAYOUT, *, offline=False):
    version = supported(version)
    if layout == DEFAULT_LAYOUT:
        # The portable firmware ZIP is distributed for the default geometry.
        home = Path(__file__).resolve().parent
        for directory in (home, home.parent):
            bundle = directory / f"RouterUpgrade-firmware-{version}.zip"
            if bundle.is_file():
                log("发现配套公开固件包，正在验证后复用。")
                result = import_firmware_bundle(bundle, public_dir, log)
                if result["version"] != version:
                    raise ValueError("公开 ZIP 的文件名与包内验证过的版本不一致。请检查下载的文件。")
                return result
    if offline:
        cached = load_verified_firmware(version, public_dir, log=log, layout=layout)
        if cached:
            return cached
        raise ValueError("离线目录中缺少与所选版本、整盘和启动分区容量匹配的已验证成品。"
                         "可选择含有匹配成品的目录，或联机按此布局构建。")
    return build_local(version, public_dir, log, layout=layout)


def supported(value):
    from engine.releases import RELEASE_KEYS
    value = release_number(value)
    if tuple(map(int, value.split(".")[:2])) not in RELEASE_KEYS or not value.startswith("25.12."):
        raise ValueError(f"检测到 {value}。当前向导支持 25.12.x；请先适配并验证该系列的发布公钥、包管理器和分区配方。")
    return value


def separate(public, private, backup, filters=None):
    public, private = checked_path(public, allow_missing=True), checked_path(private, allow_missing=True)
    if private.is_relative_to(public) or public.is_relative_to(private):
        raise ValueError("私有目录与公开目录需要分别存放，不能相同或彼此包含。")
    if checked_path(backup).is_relative_to(public) or (filters and
            (checked_path(filters).is_relative_to(public) or public.is_relative_to(checked_path(filters)))):
        raise ValueError("请将私人备份和过滤文件存放在公开目录以外。")


def terminal_review(lines):
    if not sys.stdin.isatty():
        raise ValueError("需要在本机核对排除项。请运行 GUI 或在交互终端运行。")
    print("\n这些路径只显示在本机。请先检查自定义配置：")
    for line in lines:
        print("  " + line)
    return input("按上述清单继续？输入 YES 确认：").strip() == "YES"


def main(argv=None):
    parser = argparse.ArgumentParser(description="ImmortalWrt x86 主路由升级助手")
    commands = parser.add_subparsers(dest="command", required=True)
    latest = commands.add_parser("latest", help="向官方镜像站查询最新稳定版")
    latest.add_argument("--partitions", action="store_true", help="下载并校验该版 x86/64 BIOS 镜像，读取实际分区表")
    for command, help_text in (("build", "校验或构建公开系统盘"), ("prepare", "本机生成私有恢复盘"),
                               ("run", "准备配置、验证系统盘并生成 PVE 离线交接单")):
        p = commands.add_parser(command, help=help_text)
        add_layout_arguments(p)
        p.add_argument("--version", help="固定目标版本；省略时联机查询最新稳定版")
        if command != "prepare":
            p.add_argument("--public-dir", required=True, type=Path)
        if command != "build":
            p.add_argument("--backup", required=True, type=Path, help="本地 LuCI/sysupgrade 备份")
            p.add_argument("--private-dir", required=True, type=Path, help="不同步的本地私有目录")
            p.add_argument("--filters", type=Path, help="备份缺少订阅文件时，可选的本地过滤文件目录")
    p = commands.add_parser("import", help="导入本版助手校验表中已知的公开成品 ZIP")
    p.add_argument("bundle", type=Path)
    p.add_argument("--public-dir", required=True, type=Path)
    p = commands.add_parser("verify", help="离线复核已完成的系统盘、报告和软件包清单")
    add_layout_arguments(p)
    p.add_argument("--version", required=True)
    p.add_argument("--public-dir", required=True, type=Path)
    a = parser.parse_args(argv)
    try:
        if a.command == "latest":
            version = discover_latest()
            print(version, flush=True)
            if a.partitions:
                info = official_layout(version)
                print(f"官方 BIOS/ext4 分区：/boot {info['boot_mib']:,} MiB，根分区 {info['root_mib']:,} MiB")
                print(f"{info['image_name']}  SHA-256 {info['sha256']}")
        elif a.command == "import":
            print(import_firmware_bundle(a.bundle, a.public_dir)["qcow2"])
        else:
            layout = Layout(a.disk_gib, a.boot_mib)
            if a.command == "verify":
                v = load_verified_firmware(a.version, a.public_dir, layout=layout)
                if not v:
                    raise ValueError("该目录没有匹配此版本和分区布局的验证成品。")
                print(v["sha256"], v["qcow2"])
                return 0
            version = release_number(a.version) if a.version else discover_latest()
            if a.command == "run":
                separate(a.public_dir, a.private_dir, a.backup, a.filters)
            recovery = firmware = None
            if a.command in ("run", "prepare"):
                recovery = prepare_restore(version, a.backup, a.private_dir, a.filters, terminal_review, layout=layout)
                print("本机私有恢复盘：", recovery["raw"], "\nSHA-256:", recovery["sha256"])
            if a.command in ("run", "build"):
                firmware = build_firmware(version, a.public_dir, layout=layout)
                print("公开系统盘：", firmware["qcow2"], "\nSHA-256:", firmware["sha256"])
            if a.command == "run":
                print("离线操作单：", write_guide(version, a.public_dir, firmware, recovery, layout=layout))
    except (ValueError, OSError, RuntimeError) as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
