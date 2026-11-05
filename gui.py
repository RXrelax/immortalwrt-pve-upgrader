"""Native, local-first desktop interface for the ImmortalWrt upgrade workflow."""

import importlib
import hashlib
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, font, messagebox, ttk

from engine.layout import DEFAULT_LAYOUT, Layout
from engine.localpaths import checked_path


PAPER = "#f6f8fa"
INK = "#203443"
MUTED = "#536b7a"
NAVY = "#1e3c50"
TEAL = "#13746c"
BLUE = "#225f91"
LINE = "#ccd7dd"
WHITE = "#ffffff"
ERROR = "#a2392e"
WARNING = "#875718"

PHASES = ("比较版本与分区", "制作私有恢复盘", "构建与校验固件", "生成 PVE 操作单")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def default_root():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "RouterUpgrade"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "RouterUpgrade"


def directory(value, label):
    if not value.strip():
        raise ValueError(f"请选择{label}。")
    path = checked_path(value, allow_missing=True)
    if path.exists() and not path.is_dir():
        raise ValueError(f"{label}需要是文件夹。")
    if path == Path(path.anchor) or path == Path.home().resolve():
        raise ValueError(f"请为{label}选择单独的子文件夹。")
    return path


def stable(value):
    value = value.strip()
    if not VERSION.fullmatch(value):
        raise ValueError("请输入完整的稳定版号，例如 25.12.2。")
    return value


def number(version):
    return tuple(map(int, stable(version).split(".")))


def mib_label(value):
    if int(value) == value:
        value = int(value)
    return f"{value:,} MiB"


@dataclass(frozen=True)
class Selection:
    current: str
    target: str
    public: str
    private: str
    backup: str
    filters: str
    disk_gib: str = str(DEFAULT_LAYOUT.disk_gib)
    boot_mib: str = str(DEFAULT_LAYOUT.boot_mib)
    offline: bool = False

    def layout(self):
        if not all(re.fullmatch(r"[0-9]{1,6}", str(value)) for value in (self.disk_gib, self.boot_mib)):
            raise ValueError("整盘和 /boot 容量须填写整数，单位分别为 GiB 和 MiB。")
        return Layout(int(self.disk_gib), int(self.boot_mib))

    def validate(self, action):
        if self.target and action != "bundle":
            stable(self.target)
        if self.offline and not self.target and action != "bundle":
            raise ValueError("离线使用时请指定完整的目标版本。")
        if action == "discover":
            return
        if self.current:
            stable(self.current)
        self.layout()
        public = directory(self.public, "公开构建目录")
        private = directory(self.private, "私有输出目录") if self.private or action in ("full", "recovery") else None
        if private and (private.is_relative_to(public) or public.is_relative_to(private)):
            raise ValueError("公开构建目录和私有输出目录须相互独立。请选择两个并列的子文件夹。")
        for value in (self.backup, self.filters):
            if value and checked_path(value, allow_missing=True).is_relative_to(public):
                raise ValueError("备份和过滤文件应放在公开构建目录之外。")
        if self.filters and public.is_relative_to(checked_path(self.filters, allow_missing=True)):
            raise ValueError("过滤目录不能包含公开构建目录。")
        if action in ("full", "recovery"):
            if not self.backup or not checked_path(self.backup, allow_missing=True).is_file():
                raise ValueError("请选择本机保存的 LuCI 配置备份文件。")
            if self.filters and not checked_path(self.filters, allow_missing=True).is_dir():
                raise ValueError("独立过滤文件目录不存在。可以重新选择，也可以留空使用备份内的文件。")


def private_key(selection, version):
    from engine.private_restore import local_path, regular_local
    output = local_path(Path(selection.private), output=True)
    archive = local_path(Path(selection.backup))
    if not regular_local(archive):
        raise ValueError("请选择普通的本地备份文件。")
    filters = local_path(Path(selection.filters)) if selection.filters else None
    files = tuple(sorted((p.name, file_hash(p) if p.suffix.lower() == ".txt" and regular_local(p) else "")
                         for p in filters.iterdir())) if filters else ()
    return (version, selection.layout(), str(archive), file_hash(archive), str(filters), files, str(output))


def file_hash(path):
    from engine.private_restore import regular_local
    path = checked_path(path)
    if not regular_local(path):
        raise ValueError("校验对象须为普通的本地文件。")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Stopped(Exception):
    pass


@dataclass(frozen=True)
class ReleasePreview:
    version: str
    official: dict | None
    reason: str = ""


def run_job(action, settings, bundle, engine, event, review, stopping, private_cache,
            preview=None, allow_unverified=False):
    """Worker. All UI access goes through event and review."""
    def check_stop():
        if stopping.is_set():
            raise Stopped()

    def log(message):
        event("log", str(message))

    def stage(index, status, detail):
        event("stage", (index, status, detail))

    comparing = action == "discover" or (action != "bundle" and preview is None)
    settings.validate("discover" if comparing else action)
    check_stop()
    public = checked_path(settings.public, allow_missing=True) if not comparing else None
    if action == "bundle":
        if settings.layout() != DEFAULT_LAYOUT:
            raise ValueError("公开发布 ZIP 使用默认布局。请先恢复默认容量，或选择按自定义布局构建。")
        stage(2, "active", "验证本地成品包")
        result = engine.import_firmware_bundle(checked_path(bundle), public, log)
        version = stable(result["version"])
        event("imported", version)
        stage(0, "ok", version + " · 本地成品")
        stage(2, "ok", "成品已核验并保存")
        event("firmware", result)
        return "成品已载入。可用这个版本离线准备升级。"

    if comparing:
        stage(0, "active", "读取目标版本" if settings.target else "查询最新稳定版")
        try:
            version = stable(settings.target or engine.discover_latest(log))
        except (OSError, RuntimeError) as exc:
            raise ValueError("查询正式版本失败。可重试，或选择「离线指定版本」并填写随包固件版本。\n" + str(exc)) from exc
        event("version", version)
        check_stop()
        if settings.offline:
            found = ReleasePreview(version, None, "离线模式，本次未查询官方镜像。")
        else:
            stage(0, "active", "正在下载并核验官方 BIOS 镜像")
            try:
                info = engine.official_layout(version, log)
                if info["version"] != version:
                    raise ValueError("官方分区记录的版本与目标不一致。")
                found = ReleasePreview(version, info)
            except (OSError, ValueError, RuntimeError) as exc:
                found = ReleasePreview(version, None, safe_message(str(exc)))
        check_stop()
        event("preview", found)
        stage(0, "ok" if found.official else "notice",
              f"{version} · " + ("官方布局已核验" if found.official else "官方布局未核验"))
        return "请比较分区并调整本次容量，再选择准备操作。"

    version = stable(preview.version)
    if settings.target and version != stable(settings.target):
        raise ValueError("目标版本已更改，请先重新核对官方布局。")
    if preview.official is None and not allow_unverified:
        raise ValueError("尚未核验官方布局；请先查看原因并决定是否按所选容量继续。")
    layout = settings.layout()
    event("version", version)
    stage(0, "ok", f"{version} · 已选择本次布局")
    # Check release support before reading or hashing the private backup.
    engine.supported(version)
    if settings.current and number(version) < number(settings.current):
        raise ValueError("目标版本低于填写的当前版本。请核对版本号。")
    if settings.current == version:
        log("当前版本与目标版本相同。本次将准备同版本的替换盘。")

    recovery = firmware = None
    if action in ("full", "recovery"):
        check_stop()
        stage(1, "active", "本机解析所选备份")
        key = private_key(settings, version)
        saved = private_cache.get("last")
        reuse = False
        if saved and saved[0] == key:
            try:
                reuse = (file_hash(Path(saved[1]["raw"])) == saved[1]["sha256"].lower()
                         and file_hash(Path(saved[1]["archive"])) == saved[2])
            except (OSError, ValueError):
                pass
        if reuse:
            recovery = saved[1]
            stage(1, "ok", "沿用本次会话已生成的恢复盘")
        else:
            # The interactive review may contain local filenames. Never copy its
            # details to the public build log or to persistent GUI state.
            recovery = engine.prepare_restore(
                version, checked_path(settings.backup), checked_path(settings.private, allow_missing=True),
                checked_path(settings.filters) if settings.filters else None,
                review, lambda _message: None, layout=layout,
            )
            private_cache["last"] = (key, recovery, file_hash(Path(recovery["archive"])))
            stage(1, "ok", "私有恢复盘已生成")
        event("recovery", recovery)

    if action in ("full", "firmware"):
        check_stop()
        stage(2, "active", "检查已验证成品；需要时本机构建")
        firmware = engine.build_firmware(version, public, log, layout=layout, offline=settings.offline)
        event("firmware", firmware)
        stage(2, "ok", "已取得验证结果")

    if action == "full":
        check_stop()
        stage(3, "active", "整理离线换盘步骤")
        guide = engine.write_guide(version, public, firmware, recovery, layout=layout)
        event("guide", str(guide))
        stage(3, "ok", "请打开操作单，在 PVE 切换")
        return "升级材料已就绪。进入 PVE 之前，请先保存离线操作单。"
    if action == "recovery":
        return "私有恢复盘已生成。请妥善保管恢复盘和归档。"
    return "固件构建与校验完成。"


def open_folder(path):
    path = checked_path(path)
    if not path.is_dir():
        raise ValueError("文件夹不存在。")
    if os.name == "nt":
        os.startfile(str(path))
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)])


class App:
    def __init__(self, root, engine=None):
        self.root = root
        self.engine = engine
        self.events = queue.Queue()
        self.stopping = threading.Event()
        self.running = False
        self.exit_after_stop = False
        self.private_cache = {}
        self.results = {}
        self.active = None
        self.complete_stages = set()
        self.last_action = "full"
        self.preview = None
        self.next_action = "full"
        self.stage_rows = []
        self.inputs = []
        root.title("ImmortalWrt 升级工作台")
        root.configure(bg=PAPER)
        root.geometry(f"{min(1060, root.winfo_screenwidth()-32)}x{min(720, root.winfo_screenheight()-86)}")
        root.minsize(min(700, root.winfo_screenwidth()-32), min(480, root.winfo_screenheight()-86))
        root.protocol("WM_DELETE_WINDOW", self.close)
        base = default_root()
        self.values = {key: tk.StringVar(root, value) for key, value in {
            "current": "", "target": "", "backup": "", "filters": "",
            "disk_gib": str(DEFAULT_LAYOUT.disk_gib), "boot_mib": str(DEFAULT_LAYOUT.boot_mib),
            "private": str(base / "private"), "public": str(base / "public"),
        }.items()}
        self.target_mode = tk.StringVar(root, "检测最新稳定版")
        self.status = tk.StringVar(root, "先查询目标版本，比较布局后再准备升级。")
        self.release = tk.StringVar(root, "待确认")
        self._styles()
        self._header()
        self._footer()
        self._body()
        for key, var in self.values.items():
            var.trace_add("write", lambda *args, name=key: self._inputs_changed(name))
        self.target_mode.trace_add("write", lambda *_: self._inputs_changed("target"))
        self._layout_changed()
        self.root.after(70, self._drain)

    def _styles(self):
        root = self.root
        available = set(font.families(root))
        self.family = next((f for f in ("Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
                                        "Noto Sans CJK SC") if f in available), "TkDefaultFont")
        normal = (self.family, 10)
        root.option_add("*Font", normal)
        self.style = s = ttk.Style(root)
        s.theme_use("clam")
        s.configure(".", font=normal, foreground=INK, background=PAPER)
        s.configure("TEntry", fieldbackground=WHITE, bordercolor=LINE, lightcolor=LINE,
                    darkcolor=LINE, padding=(6, 5), insertcolor=INK)
        s.map("TEntry", bordercolor=[("focus", BLUE)])
        s.configure("TCombobox", fieldbackground=WHITE, arrowsize=14, padding=4)
        s.map("TCombobox", fieldbackground=[("readonly", WHITE)])
        s.configure("TButton", background=WHITE, bordercolor=LINE, focuscolor=BLUE,
                    lightcolor=LINE, darkcolor=LINE, padding=(10, 5))
        s.map("TButton", background=[("active", "#e4eef2"), ("disabled", PAPER)])
        s.configure("Main.TButton", background=TEAL, foreground=WHITE, padding=(16, 9),
                    bordercolor=TEAL, lightcolor=TEAL, darkcolor=TEAL, focuscolor=WHITE,
                    font=(self.family, 10, "bold"))
        s.map("Main.TButton", background=[("disabled", "#6e8b89"), ("active", "#0f605a")],
              foreground=[("disabled", WHITE)])
        s.configure("TNotebook", borderwidth=0, background=PAPER)
        s.configure("TNotebook.Tab", padding=(13, 6), background="#e6edf0")
        s.map("TNotebook.Tab", background=[("selected", WHITE)], foreground=[("selected", BLUE)])
        s.configure("Horizontal.TProgressbar", troughcolor="#e0e8e9", background=TEAL, thickness=3)

    def label(self, parent, content, color=INK, size=10, bold=False, bg=PAPER, **opts):
        return tk.Label(parent, text=content, fg=color, bg=bg, anchor="w", justify="left",
                        font=(self.family, size, "bold" if bold else "normal"), **opts)

    def _header(self):
        banner = tk.Frame(self.root, bg=PAPER, padx=18, pady=12)
        banner.pack(fill="x")
        self.label(banner, "ImmortalWrt 升级工作台", INK, 17, True).pack(side="left")
        self.label(banner, "PVE  /  x86-64  /  SeaBIOS", MUTED, 10).pack(side="right")

    def _footer(self):
        bottom = tk.Frame(self.root, bg=WHITE, padx=18, pady=11)
        bottom.pack(side="bottom", fill="x")
        self.primary = ttk.Button(bottom, text="查询版本与分区", style="Main.TButton",
                                  command=lambda: self.start(self.next_action))
        self.primary.pack(side="right")
        self.more = ttk.Menubutton(bottom, text="其他操作 ▾", direction="above")
        menu = tk.Menu(self.more, tearoff=False)
        for title, action in (("重新核对版本与分区", "discover"), ("准备完整升级材料", "full"), ("仅生成私有恢复盘", "recovery"),
                              ("仅构建和验证公开固件", "firmware"), ("载入已验证成品 ZIP…", "bundle")):
            menu.add_command(label=title, command=lambda a=action: self.start(a))
        self.more.configure(menu=menu)
        self.more.pack(side="right", padx=8)
        self.stop_btn = ttk.Button(bottom, text="本阶段后停止", command=self.stop)
        status = self.label(bottom, "", MUTED, 9, bg=WHITE, textvariable=self.status, wraplength=380)
        status.pack(side="left", fill="x", expand=True, anchor="w")
        status.bind("<Configure>", lambda e: status.configure(wraplength=max(60, e.width - 4)))

    def _body(self):
        content = tk.Frame(self.root, bg=PAPER, padx=14, pady=12)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)
        self.tabs = ttk.Notebook(content)
        self.tabs.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.layout_page = self._tab("版本与分区")
        self._layout_form(self.layout_page)
        self.files_page = self._tab("备份与输出")
        self._files_form(self.files_page)
        self.log_page = tk.Frame(self.tabs, bg=WHITE)
        self.tabs.add(self.log_page, text="运行记录")
        self.log_text = tk.Text(self.log_page, wrap="word", relief="flat", padx=14, pady=12,
                                bg=WHITE, fg=INK, state="disabled", width=18, height=10)
        scroll = ttk.Scrollbar(self.log_page, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)
        panel = tk.Frame(content, bg=PAPER)
        panel.grid(row=0, column=1, sticky="ns", padx=(0, 4))
        panel.columnconfigure(0, weight=1)
        self.label(panel, "执行进度", size=12, bold=True).grid(row=0, column=0, sticky="w", pady=(3, 6))
        groups = []
        for i, name in enumerate(PHASES):
            group = tk.Frame(panel, bg=PAPER)
            groups.append(group)
            group.grid(row=i+1, column=0, sticky="ew", pady=(3, 6))
            num = self.label(group, f"{i+1}.", MUTED, 10)
            num.pack(side="left", anchor="n", padx=(0, 6))
            body = tk.Frame(group, bg=PAPER)
            body.pack(side="left", fill="x", expand=True)
            name_label = self.label(body, name, INK, 10, True)
            name_label.pack(anchor="w")
            desc = self.label(body, "待执行", MUTED, 9, wraplength=145)
            desc.pack(anchor="w")
            self.stage_rows.append((num, name_label, desc))
        self.progress = ttk.Progressbar(panel, mode="determinate", maximum=4, length=170)
        self.progress.grid(row=5, column=0, sticky="ew", pady=(5, 12))
        self.results_btn = ttk.Button(panel, text="查看生成文件", state="disabled", command=self.show_results)
        self.results_btn.grid(row=6, column=0, sticky="ew", pady=(0, 5))
        self.guide_btn = ttk.Button(panel, text="打开离线操作单", state="disabled", command=self.open_guide)
        self.guide_btn.grid(row=7, column=0, sticky="ew")
        # On a smaller desktop, keep results and handoff controls reachable
        # without squeezing the capacity comparison into a narrow column.
        self.steps_tab = False
        def adapt(event):
            compact = (event.width < self.root.winfo_fpixels("600p")
                       or event.height < self.root.winfo_fpixels("290p"))
            if compact == self.steps_tab:
                return
            self.steps_tab = compact
            if compact:
                panel.grid_remove()
                self.tabs.add(panel, text="执行进度")
                self.tabs.grid_configure(padx=0)
                for i, group in enumerate(groups):
                    group.grid_configure(row=1+i//2, column=i%2, padx=6)
                self.progress.grid_configure(row=3, columnspan=2)
                self.results_btn.grid_configure(row=4, column=0)
                self.guide_btn.grid_configure(row=4, column=1, pady=(0, 5))
                panel.columnconfigure(1, weight=1)
            else:
                self.tabs.forget(panel)
                for i, group in enumerate(groups):
                    group.grid_configure(row=i+1, column=0, padx=0)
                self.progress.grid_configure(row=5, columnspan=1)
                self.results_btn.grid_configure(row=6, column=0)
                self.guide_btn.grid_configure(row=7, column=0, pady=0)
                panel.columnconfigure(1, weight=0)
                panel.grid()
                self.tabs.grid_configure(padx=(0, 12))
        content.bind("<Configure>", adapt)

    def _tab(self, title):
        form_page = tk.Frame(self.tabs, bg=WHITE)
        self.tabs.add(form_page, text=title)
        canvas = tk.Canvas(form_page, bg=WHITE, bd=0, highlightthickness=0, width=320)
        bar = ttk.Scrollbar(form_page, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        fields = tk.Frame(canvas, bg=WHITE, padx=16, pady=11)
        inner = canvas.create_window((0, 0), window=fields, anchor="nw")
        fields.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(inner, width=e.width))
        def wheel(e):
            over = self.root.winfo_containing(e.x_root, e.y_root)
            if over is not None and str(over).startswith(str(form_page) + "."):
                step = -1 if getattr(e, "num", None) == 4 or getattr(e, "delta", 0) > 0 else 1
                canvas.yview_scroll(step * 2, "units")
        for event_name in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.root.bind(event_name, wheel, add="+")
        return fields

    def _layout_form(self, parent):
        self.label(parent, "目标固件", INK, 13, True, WHITE).pack(anchor="w")
        row = tk.Frame(parent, bg=WHITE)
        row.pack(fill="x", pady=(5, 6))
        mode = ttk.Combobox(row, textvariable=self.target_mode, state="readonly", width=15,
                            values=("检测最新稳定版", "指定稳定版", "离线指定版本"))
        mode.pack(side="left")
        self.inputs.append((mode, "readonly"))
        self.target_entry = ttk.Entry(row, width=10, textvariable=self.values["target"])
        self.query_btn = ttk.Button(row, text="重新查询", command=lambda: self.start("discover"))
        self.inputs.append((self.query_btn, "normal"))
        self.label(parent, "", BLUE, 11, True, WHITE, textvariable=self.release).pack(anchor="w")
        ttk.Separator(parent).pack(fill="x", pady=(12, 8))

        self.label(parent, "分区对比", INK, 13, True, WHITE).pack(anchor="w")
        table = tk.Frame(parent, bg=WHITE)
        table.pack(fill="x", pady=(6, 5))
        for col in range(3):
            table.columnconfigure(col, weight=1, uniform="layout")
        for col, title in enumerate(("分区", "官方默认", "本次系统盘")):
            self.label(table, title, MUTED, 9, bg=WHITE).grid(
                row=0, column=col, sticky="w" if col == 0 else "e", pady=(1, 3))
        self.official_boot = tk.StringVar(self.root, "—")
        self.official_root = tk.StringVar(self.root, "—")
        self.selected_boot = tk.StringVar(self.root)
        self.selected_root = tk.StringVar(self.root)
        for i, (title, off, target) in enumerate((
            ("启动分区 /boot", self.official_boot, self.selected_boot),
            ("根分区 /", self.official_root, self.selected_root),
        ), 1):
            self.label(table, title, INK, 10, bg=WHITE).grid(row=i, column=0, sticky="w", pady=3)
            self.label(table, "", INK, 12, bg=WHITE, textvariable=off).grid(row=i, column=1, sticky="e")
            self.label(table, "", TEAL, 12, True, WHITE, textvariable=target).grid(row=i, column=2, sticky="e")
        self.source_state = tk.StringVar(self.root, "官方 BIOS / ext4 镜像待查询。")
        source_row = tk.Frame(parent, bg=WHITE)
        source_row.pack(fill="x", pady=(1, 0))
        self.source_btn = ttk.Button(source_row, text="查看依据", command=self.show_source, state="disabled")
        self.source_btn.pack(side="right")
        self.source_label = self.label(source_row, "", MUTED, 9, bg=WHITE, textvariable=self.source_state,
                                       wraplength=300)
        self.source_label.pack(side="left", expand=True, fill="x")
        ttk.Separator(parent).pack(fill="x", pady=(11, 7))

        self.label(parent, "本次磁盘容量", INK, 13, True, WHITE).pack(anchor="w")
        controls = tk.Frame(parent, bg=WHITE)
        controls.pack(fill="x", pady=4)
        for col, (key, title) in enumerate((("disk_gib", "整盘容量（GiB）"), ("boot_mib", "/boot（MiB）"))):
            block = tk.Frame(controls, bg=WHITE)
            block.grid(row=0, column=col, sticky="ew", padx=(0, 10))
            self.label(block, title, MUTED, 9, bg=WHITE).pack(anchor="w")
            entry = ttk.Entry(block, width=11, textvariable=self.values[key])
            entry.pack(fill="x")
            self.inputs.append((entry, "normal"))
            controls.columnconfigure(col, weight=1)
        reset = ttk.Button(controls, text="恢复默认", command=self.reset_layout)
        reset.grid(row=0, column=2, sticky="se")
        self.inputs.append((reset, "normal"))
        self.layout_note = self.label(parent, "", MUTED, 9, bg=WHITE, wraplength=465)
        self.layout_note.pack(fill="x", pady=(3, 1))
        self._target_changed()

    def _files_form(self, parent):
        def heading(title):
            self.label(parent, title, size=13, bold=True, bg=WHITE).pack(anchor="w", pady=(6, 3))

        def chooser(title, key, picker):
            block = tk.Frame(parent, bg=WHITE)
            block.pack(fill="x", pady=(3, 4))
            self.label(block, title, MUTED, 9, bg=WHITE).pack(anchor="w")
            row = tk.Frame(block, bg=WHITE)
            row.pack(fill="x")
            entry = ttk.Entry(row, textvariable=self.values[key])
            entry.pack(side="left", expand=True, fill="x")
            btn = ttk.Button(row, text="选择…", command=lambda: self.pick(key, picker, title))
            btn.pack(side="left", padx=(5, 0))
            self.inputs.extend(((entry, "normal"), (btn, "normal")))

        heading("原系统版本")
        self.label(parent, "当前使用的完整版本（选填）", MUTED, 9, bg=WHITE).pack(anchor="w")
        current = ttk.Entry(parent, width=15, textvariable=self.values["current"])
        current.pack(anchor="w", pady=(2, 8))
        self.inputs.append((current, "normal"))
        heading("配置恢复")
        self.label(parent, "备份仅在本机处理。请选择不同步到云盘的输出文件夹。", MUTED, 9, bg=WHITE,
                   wraplength=430).pack(anchor="w")
        chooser("LuCI 备份文件（.tar.gz 或 .tgz）", "backup", "file")
        chooser("私有恢复盘输出目录", "private", "folder")
        chooser("独立 ADH 过滤文件目录（备份中已有时留空）", "filters", "folder")
        ttk.Separator(parent).pack(fill="x", pady=(9, 3))
        heading("公开固件")
        chooser("构建缓存与成品目录", "public", "folder")

    def pick(self, key, picker, title):
        if picker == "file":
            value = filedialog.askopenfilename(parent=self.root, title=title, filetypes=[
                ("LuCI 配置备份", "*.tar.gz *.tgz"), ("所有文件", "*")])
        else:
            value = filedialog.askdirectory(parent=self.root, title=title)
        if value:
            self.values[key].set(value)

    def _target_changed(self):
        if self.target_mode.get() == "检测最新稳定版":
            self.target_entry.pack_forget()
        else:
            self.target_entry.pack(side="left", padx=5)
            self.target_entry.configure(state="disabled" if self.running else "normal")

    def reset_layout(self):
        self.values["disk_gib"].set(str(DEFAULT_LAYOUT.disk_gib))
        self.values["boot_mib"].set(str(DEFAULT_LAYOUT.boot_mib))

    def _layout_changed(self):
        try:
            layout = self._settings().layout()
        except ValueError as exc:
            self.selected_boot.set("—")
            self.selected_root.set("—")
            self.layout_note.configure(text=str(exc), fg=ERROR)
            return
        self.selected_boot.set(f"{layout.boot_mib:,} MiB")
        self.selected_root.set(f"{layout.root_mib:,} MiB")
        if layout == DEFAULT_LAYOUT:
            note = "默认布局可复用同版本的已验证成品；完整便携包随附 25.12.2。"
        else:
            note = "自定义布局会使用单独的成品目录。首次构建需要本机 Docker 的 Linux 引擎。"
        self.layout_note.configure(text=note, fg=MUTED)

    def _show_preview(self, preview):
        self.preview = preview
        self.release.set(f"ImmortalWrt  {preview.version}" if preview else "待确认")
        if preview and not self._settings().offline:
            self.query_btn.pack(side="right")
        else:
            self.query_btn.pack_forget()
        info = preview.official if preview else None
        if info:
            self.official_boot.set(mib_label(info["boot_mib"]))
            self.official_root.set(mib_label(info["root_mib"]))
            self.source_state.set("已核验官方 BIOS / ext4 镜像及签名清单。")
        else:
            self.official_boot.set("—")
            self.official_root.set("—")
            if preview:
                self.source_state.set("官方布局未核验。可查看原因、重新查询或自行决定是否继续。")
            else:
                self.source_state.set("官方 BIOS / ext4 镜像待查询。")
        self.source_btn.configure(state="normal" if preview else "disabled")
        self.source_label.configure(fg=WARNING if preview and not info else MUTED)

    def show_source(self):
        preview = self.preview
        if not preview:
            return
        if preview.official:
            info = preview.official
            text = (f"ImmortalWrt {preview.version} · x86/64 · BIOS / ext4\n\n"
                    f"{info['image_name']}\nSHA-256  {info['sha256']}")
            for i, p in enumerate(info["partitions"], 1):
                text += f"\n\nP{i} 起点 {p['start']:,} 字节，长度 {p['bytes']:,} 字节"
            hint = "取自 ImmortalWrt 官方发布目录，以核验过的磁盘 MBR 为准。"
        else:
            text = preview.reason
            hint = f"ImmortalWrt {preview.version} 的官方分区容量尚未核验。"
        self.detail_dialog("官方镜像依据", text, hint)

    def _update_primary(self):
        titles = {"full": "按此布局准备升级", "firmware": "按此布局准备固件", "recovery": "按此布局制作恢复盘"}
        first = "查看离线布局" if self._settings().offline else "查询版本与分区"
        self.primary.configure(text=titles[self.next_action] if self.preview else first,
                               command=lambda: self.start(self.next_action))

    def _inputs_changed(self, name):
        if self.running:
            return
        if name in ("disk_gib", "boot_mib"):
            self._layout_changed()
        if name == "target":
            self._target_changed()
            self._show_preview(None)
        self.results.clear()
        self.private_cache.clear()
        self.results_btn.configure(state="disabled")
        self.guide_btn.configure(state="disabled")
        self.complete_stages = set()
        self.active = None
        for i in range(len(PHASES)):
            self._stage(i, "idle", "待执行")
        if self.preview:
            self._stage(0, "ok" if self.preview.official else "notice",
                        f"{self.preview.version} · " + ("已核验" if self.preview.official else "官方布局未核验"))
        self.progress.configure(value=len(self.complete_stages))
        self.status.set("请比较分区并核对本次容量。" if self.preview else "先查询目标版本，比较布局后再准备升级。")
        self._update_primary()

    def _settings(self):
        values = {k: v.get().strip() for k, v in self.values.items()}
        if self.target_mode.get() == "检测最新稳定版":
            values["target"] = ""
        return Selection(**values, offline=self.target_mode.get() == "离线指定版本")

    def _busy(self, busy):
        self.running = busy
        for widget, normal in self.inputs:
            widget.configure(state="disabled" if busy else normal)
        self._target_changed()
        self.primary.configure(state="disabled" if busy else "normal")
        self.more.configure(state="disabled" if busy else "normal")
        if busy:
            self.stop_btn.configure(state="normal")
            self.stop_btn.pack(side="right", before=self.more)
            self.progress.configure(mode="indeterminate", maximum=100)
            self.progress.start(30)
        else:
            self.stop_btn.pack_forget()
            self.progress.stop()
            self.progress.configure(mode="determinate", maximum=4, value=len(self.complete_stages))

    def start(self, action):
        if self.running:
            return
        settings = self._settings()
        if action in ("full", "firmware", "recovery"):
            self.next_action = action
        comparing = action == "discover" or (action != "bundle" and self.preview is None)
        try:
            if self.target_mode.get() != "检测最新稳定版" and not settings.target and action != "bundle":
                raise ValueError("请填写完整的目标稳定版，例如 25.12.2。")
            settings.validate("discover" if comparing else action)
        except (ValueError, OSError) as exc:
            if action in ("full", "recovery") and not comparing and not settings.backup:
                self.tabs.select(1)
            messagebox.showerror("检查升级资料", str(exc), parent=self.root)
            return
        preview = None if comparing else self.preview
        allow_unverified = False
        if preview and not preview.official and action != "bundle":
            layout = settings.layout()
            allow_unverified = messagebox.askyesno(
                "官方分区未核验",
                f"{preview.version} 的官方分区容量未知。\n{preview.reason}\n\n"
                f"继续按整盘 {layout.disk_gib} GiB、/boot {layout.boot_mib} MiB 准备？",
                default=messagebox.NO, parent=self.root)
            if not allow_unverified:
                return
        bundle = None
        if action == "bundle":
            bundle = filedialog.askopenfilename(parent=self.root, title="选择公开固件成品 ZIP",
                                                 filetypes=[("固件成品", "*.zip")])
            if not bundle:
                return
        self.stopping.clear()
        self.exit_after_stop = False
        self.last_action = action
        if comparing:
            self._show_preview(None)
            self.tabs.select(0)
        self.active = None
        self.complete_stages = set()
        self.results.clear()
        self.results_btn.configure(state="disabled")
        self.guide_btn.configure(state="disabled")
        stages = (0,) if comparing else {"full": (0, 1, 2, 3), "recovery": (0, 1),
                                         "firmware": (0, 2), "bundle": (0, 2)}[action]
        for i in range(4):
            self._stage(i, "idle", "待执行" if i in stages else "本次未选择")
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.status.set("正在执行…")
        self._busy(True)

        def worker():
            try:
                engine = self.engine or importlib.import_module("upgrade")
                result = run_job(action, settings, bundle, engine, self._send,
                                 self._review, self.stopping, self.private_cache,
                                 preview=preview, allow_unverified=allow_unverified)
                self._send("done", result)
            except Stopped:
                self._send("stopped", "已在阶段边界停止。完成的本地文件仍然可用。")
            except Exception as exc:
                if getattr(exc, "details", ()):
                    self._send("private_issue", list(exc.details))
                self._send("failed", safe_message(str(exc)) or type(exc).__name__)
        threading.Thread(target=worker, daemon=False, name="router-upgrade").start()

    def _send(self, kind, value):
        self.events.put((kind, value))

    def _review(self, details):
        if self.stopping.is_set():
            raise Stopped()
        reply = threading.Event()
        result = []
        self._send("review", (list(details), reply, result))
        reply.wait()
        return bool(result and result[0])

    def _stage(self, i, status, detail):
        color = {"active": BLUE, "ok": TEAL, "notice": WARNING, "error": ERROR, "idle": MUTED}[status]
        self.stage_rows[i][0].configure(fg=color)
        self.stage_rows[i][1].configure(fg=color if status != "idle" else INK)
        self.stage_rows[i][2].configure(text=detail, fg=color)
        if status == "active":
            self.active = i
            self.status.set(detail)
        elif status in ("ok", "notice"):
            self.complete_stages.add(i)

    def _append(self, text):
        text = safe_message(text)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", time.strftime("%H:%M:%S") + "  " + text + "\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 650:
            self.log_text.delete("1.0", "80.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _drain(self):
        for _ in range(100):
            try:
                kind, data = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "stage":
                self._stage(*data)
            elif kind == "log":
                self._append(data)
            elif kind in ("version", "imported"):
                self.release.set(f"ImmortalWrt  {data}")
                if kind == "imported":
                    self.values["target"].set(data)
                    self.target_mode.set("离线指定版本")
                    self._show_preview(ReleasePreview(data, None, "已验证公开成品；尚未联机核对官方默认镜像。"))
            elif kind == "preview":
                self._show_preview(data)
            elif kind in ("firmware", "recovery", "guide"):
                self.results[kind] = data
                self.results_btn.configure(state="normal")
                if kind == "guide":
                    self.guide_btn.configure(state="normal")
            elif kind == "review":
                details, done, result = data
                try:
                    result.append(not self.stopping.is_set() and
                                  self.detail_dialog("本机核对恢复项目", "\n".join(details),
                                  "这些条目由本机备份得出。需要其中的内容时，请取消并补齐。", True))
                finally:
                    done.set()
            elif kind == "private_issue":
                self.detail_dialog("备份需要补充内容", "\n".join(data),
                                   "请在本机核对这些具体项目，再用更新后的备份重试。")
            elif kind in ("failed", "done", "stopped"):
                if kind == "failed":
                    if self.active is not None:
                        self._stage(self.active, "error", "未完成 · 查看运行记录")
                    self._append(data)
                    self.tabs.select(self.log_page)
                    self.status.set("该步骤未完成。处理提示后可重新执行。")
                else:
                    self.status.set(data)
                    self._append(data)
                self._busy(False)
                if kind == "failed":
                    self.primary.configure(text="重试本次操作", command=lambda: self.start(self.last_action))
                else:
                    self._update_primary()
                if self.exit_after_stop:
                    self.root.destroy()
                    return
        self.root.after(70, self._drain)

    def detail_dialog(self, title, text, hint, confirm=False, folders=()):
        accepted = []
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.geometry("740x420")
        dlg.configure(bg=PAPER, padx=15, pady=12)
        self.label(dlg, title, size=15, bold=True).pack(anchor="w")
        self.label(dlg, hint, MUTED, 9, wraplength=670).pack(anchor="w", pady=(4, 8))
        actions = tk.Frame(dlg, bg=PAPER)
        actions.pack(side="bottom", fill="x", pady=(9, 0))
        dismiss = ttk.Button(actions, text="取消" if confirm else "关闭", command=dlg.destroy)
        dismiss.pack(side="right")
        if confirm:
            ttk.Button(actions, text="接受所列项并继续",
                       command=lambda: (accepted.append(True), dlg.destroy())).pack(side="right", padx=7)
        for label, directory_path in folders:
            def open_result(p=directory_path):
                try:
                    open_folder(p)
                except (OSError, ValueError) as exc:
                    messagebox.showerror("无法打开目录", str(exc), parent=dlg)
            ttk.Button(actions, text=label, command=open_result).pack(side="left", padx=(0, 5))
        text_frame = tk.Frame(dlg, bg=WHITE)
        text_frame.pack(fill="both", expand=True)
        view = tk.Text(text_frame, wrap="word", padx=10, pady=8, relief="flat", bg=WHITE, fg=INK)
        scroll = ttk.Scrollbar(text_frame, command=view.yview)
        view.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        view.pack(fill="both", expand=True)
        view.insert("1.0", text)
        view.configure(state="disabled")
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.grab_set()
        dismiss.focus_set()
        self.root.wait_window(dlg)
        return bool(accepted)

    def show_results(self):
        lines = []
        folders = []
        for category, fields in (("recovery", (("私有恢复盘", "raw"), ("本地备份", "archive"), ("恢复盘 SHA-256", "sha256"))),
                                 ("firmware", (("系统盘", "qcow2"), ("系统盘 SHA-256", "sha256"),
                                               ("验证记录", "verification"), ("软件清单", "manifest")))):
            block = self.results.get(category, {})
            sample = block.get("raw") if category == "recovery" else block.get("qcow2")
            if sample:
                folders.append(("打开私有目录" if category == "recovery" else "打开固件目录", Path(sample).parent))
            for label, key in fields:
                if block.get(key):
                    lines.extend((label, str(block[key]), ""))
        if self.results.get("guide"):
            lines.extend(("PVE 离线操作单", str(self.results["guide"])))
        self.detail_dialog("本次生成文件", "\n".join(lines), "可以在此选中并复制路径及校验值。私有恢复盘仅交给你自己的 PVE。", folders=folders)

    def open_guide(self):
        try:
            path = checked_path(self.results.get("guide", ""))
        except (ValueError, OSError):
            messagebox.showerror("无法打开", "请重新执行，生成可验证位置的本地操作单。", parent=self.root)
            return
        if not path.is_file() or path.suffix.lower() != ".html":
            messagebox.showerror("无法打开", "尚无可用的本地 HTML 操作单。", parent=self.root)
            return
        webbrowser.open(path.as_uri())

    def stop(self):
        self.stopping.set()
        self.status.set("已请求停止，等待当前阶段完成。")
        self.stop_btn.configure(state="disabled")

    def close(self):
        if self.running:
            if messagebox.askyesno("任务正在运行", "等待当前阶段完成，停止后续步骤并退出？", parent=self.root):
                self.exit_after_stop = True
                self.stop()
        else:
            self.root.destroy()


def safe_message(text):
    # Build redirects can include expiring signed URLs; logs only need the origin and path.
    text = re.sub(r"(https?://[^\s?#]+)\?[^\s]+", r"\1?[省略]", text)
    return re.sub(r"(https?://)[^\s/@]+@", r"\1", text)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
