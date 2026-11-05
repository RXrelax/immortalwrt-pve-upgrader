import hashlib
import os
import time
import tkinter as tk
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gui import App, ReleasePreview, Selection, Stopped, mib_label, run_job, safe_message
from engine.layout import DEFAULT_LAYOUT, Layout
from engine.localpaths import checked_path


class Engine:
    """Synthetic backend for the interaction contract; no Docker or network."""
    def __init__(self):
        self.calls = []
        self.layouts = []

    def discover_latest(self, log):
        self.calls.append("discover")
        return "25.12.2"

    def supported(self, version):
        if not version.startswith("25.12."):
            raise ValueError("目标系列尚未适配")

    def official_layout(self, version, log):
        self.calls.append("official")
        return {"version": version, "boot_mib": 32, "root_mib": 300,
                "partitions": [{"start": 262144, "bytes": 33554432}],
                "image_name": "synthetic-official.img.gz", "sha256": "a" * 64}

    def prepare_restore(self, version, source, dest, filters, review, log, layout):
        self.calls.append("restore")
        self.layouts.append(("restore", layout))
        log("do not show private command output")
        if not review(["synthetic-item"]):
            raise ValueError("用户取消")
        dest.mkdir(exist_ok=True)
        raw, archive = dest / "fixture.raw", dest / "fixture.tgz"
        raw.write_bytes(source.read_bytes() + b"-fixture")
        archive.write_bytes(b"SYNTHETIC")
        return {"raw": raw, "archive": archive, "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}

    def build_firmware(self, version, public, log, layout, offline):
        self.calls.append("build")
        self.layouts.append(("build", layout, offline))
        return {"qcow2": public / "fw.qcow2"}

    def write_guide(self, version, public, firmware, recovery, layout):
        self.calls.append("guide")
        self.layouts.append(("guide", layout))
        assert firmware["qcow2"] and recovery["raw"]
        return public / "guide.html"

    def import_firmware_bundle(self, bundle, public, log):
        self.calls.append("bundle")
        return {"version": "25.12.2", "qcow2": public / "fw.qcow2"}


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.backup = self.base / "fixture.tgz"
        self.backup.write_bytes(b"SYNTHETIC")
        (self.base / "fixture.zip").write_bytes(b"SYNTHETIC PUBLIC")
        self.cache = {}
        self.log = []
        self.engine = Engine()
        self.flag = Event()

    def selection(self, **changes):
        opts = dict(current="24.10.6", target="", public=str(self.base/"public"),
                    private=str(self.base/"private"), backup=str(self.backup), filters="")
        return Selection(**(opts | changes))

    def run_action(self, action, selection=None, accept=True, preview=True, allow_unverified=False):
        sel = selection or self.selection()
        if preview is True:
            preview = ReleasePreview(sel.target or "25.12.2", {"version": sel.target or "25.12.2"})
        return run_job(action, sel, self.base/"fixture.zip", self.engine,
                       lambda k, v: self.log.append((k, v)), lambda _d: accept, self.flag, self.cache,
                       preview=preview, allow_unverified=allow_unverified)

    def test_full_flow_and_verified_retry(self):
        self.run_action("full")
        self.assertEqual(self.engine.calls, ["restore", "build", "guide"])
        self.assertNotIn(("log", "do not show private command output"), self.log)
        self.assertEqual([v for k,v in self.log if k == "review"], [])
        self.engine.calls.clear()
        self.run_action("full", self.selection(target="25.12.2"))
        self.assertEqual(self.engine.calls, ["build", "guide"])
        (self.base/"private"/"fixture.raw").write_bytes(b"changed")
        self.run_action("recovery", self.selection(target="25.12.2"))
        self.assertEqual(self.engine.calls[-1], "restore")
        self.backup.write_bytes(b"CHANGED")
        self.run_action("recovery", self.selection(target="25.12.2"))
        self.assertEqual(self.engine.calls.count("restore"), 2)

    def test_declined_review_stops_before_build(self):
        with self.assertRaisesRegex(ValueError, "取消"):
            self.run_action("full", accept=False)
        self.assertEqual(self.engine.calls, ["restore"])
        self.assertFalse((self.base/"private").exists())

    def test_path_overlap_rejected_before_network(self):
        for changes in (dict(public=str(self.base)), dict(private=str(self.base/"public"/"inner")),
                        dict(filters=str(self.base))):
            with self.subTest(changes), self.assertRaises(ValueError):
                self.run_action("full", self.selection(**changes))
        self.assertEqual(self.engine.calls, [])

    def test_separate_actions_and_version_guard(self):
        self.run_action("firmware", self.selection(target="25.12.2",backup=""))
        self.run_action("bundle", self.selection(backup=""))
        self.assertEqual(self.engine.calls, ["build", "bundle"])
        with self.assertRaisesRegex(ValueError, "低于"):
            self.run_action("recovery", self.selection(current="26.1.1", target="25.12.2"))
        with self.assertRaisesRegex(ValueError, "稳定版号"):
            self.run_action("full", self.selection(target="25.12.3-rc1"))

    def test_external_path_rejected_without_network(self):
        for value in ("https://example.invalid/backup.tgz", "//example.invalid/share/backup.tgz"):
            with self.subTest(value), self.assertRaisesRegex(ValueError, "本机磁盘"):
                self.run_action("full", self.selection(backup=value))
        self.assertEqual(self.engine.calls, [])

    def test_unsupported_release_checked_before_private_content(self):
        with patch("gui.private_key", side_effect=AssertionError("read a backup too soon")):
            with self.assertRaisesRegex(ValueError, "尚未适配"):
                self.run_action("full", self.selection(target="26.1.0"))

    def test_offline_retry_is_an_explicit_version_choice(self):
        with patch.object(self.engine, "discover_latest", side_effect=RuntimeError("offline")):
            with self.assertRaisesRegex(ValueError, "离线指定版本"):
                self.run_action("full", preview=None)
            self.run_action("full", self.selection(target="25.12.2"))
        self.assertEqual(self.engine.calls, ["restore", "build", "guide"])

    def test_failed_public_build_retry_reuses_only_verified_private_inputs(self):
        sel = self.selection(target="25.12.2")
        with patch.object(self.engine, "build_firmware", side_effect=RuntimeError("synthetic build failure")):
            with self.assertRaisesRegex(RuntimeError, "build failure"):
                self.run_action("full", sel)
        self.run_action("full", sel)
        self.assertEqual(self.engine.calls, ["restore", "build", "guide"])

    def test_discover_only_ignores_storage_fields(self):
        with patch("gui.checked_path", side_effect=AssertionError("checked an unrelated location")):
            self.run_action("discover", self.selection(public="//example.invalid/share"))
        self.assertEqual(self.engine.calls, ["discover", "official"])

    def test_first_full_action_only_reports_official_geometry_and_allows_edit(self):
        self.assertEqual(mib_label(32.0), "32 MiB")
        self.assertEqual(mib_label(300.125), "300.125 MiB")
        with patch("gui.private_key", side_effect=AssertionError("private read before comparison")):
            self.run_action("full", self.selection(backup="", disk_gib=""), preview=None)
        self.assertEqual(self.engine.calls, ["discover", "official"])
        preview, = (v for k, v in self.log if k == "preview")
        self.assertEqual(preview.official["root_mib"], 300)
        self.assertFalse((self.base / "private").exists())
        custom = self.selection(disk_gib="20", boot_mib="768")
        self.run_action("full", custom, preview=preview)
        self.run_action("full", self.selection(), preview=preview)
        self.assertEqual(self.engine.layouts,
                         [("restore", Layout(20, 768)), ("build", Layout(20, 768), False),
                          ("guide", Layout(20, 768)), ("restore", DEFAULT_LAYOUT),
                          ("build", DEFAULT_LAYOUT, False), ("guide", DEFAULT_LAYOUT)])
        with self.assertRaisesRegex(ValueError, "版本已更改"):
            self.run_action("full", self.selection(target="25.12.3"), preview=preview)

    def test_unavailable_or_offline_layout_requires_explicit_choice(self):
        with patch.object(self.engine, "official_layout", side_effect=RuntimeError("verify failed")):
            self.run_action("discover", preview=None)
        preview, = (v for k, v in self.log if k == "preview")
        self.assertIsNone(preview.official)
        self.assertIn("verify failed", preview.reason)
        with self.assertRaisesRegex(ValueError, "尚未核验"):
            self.run_action("full", preview=preview)
        self.log.clear()
        self.engine.calls.clear()
        offline = self.selection(target="25.12.2", offline=True)
        self.run_action("full", offline, preview=None)
        self.assertEqual(self.engine.calls, [])
        manual, = (v for k, v in self.log if k == "preview")
        self.run_action("firmware", offline, preview=manual, allow_unverified=True)
        self.assertEqual(self.engine.layouts, [("build", DEFAULT_LAYOUT, True)])

    def test_incompatible_dimensions_rejected_before_private_reads(self):
        for params in [{"disk_gib": "1"}, {"boot_mib": "0"}, {"disk_gib": "2", "boot_mib": "1536"},
                       {"disk_gib": "3.5"}, {"disk_gib": "inf"}, {"boot_mib": ""}]:
            with self.subTest(params), self.assertRaises(ValueError):
                self.run_action("full", self.selection(**params))
        with self.assertRaisesRegex(ValueError, "默认布局"):
            self.run_action("bundle", self.selection(disk_gib="20"))
        self.assertEqual(self.engine.calls, [])

    def test_remote_locations_rejected_before_lstat(self):
        with patch.object(Path, "lstat", side_effect=AssertionError("followed external path")):
            for p in ("//example.invalid/share", r"\\server\share", "https://example.invalid/a",
                      "https:/example.invalid/a"):
                with self.subTest(p=p), self.assertRaises(ValueError):
                    checked_path(p, allow_missing=True)

    @unittest.skipUnless(os.name == "nt", "Windows mapped drive boundary")
    def test_mapped_drive_rejected_before_stat(self):
        import ctypes
        with patch.object(ctypes.windll.kernel32, "GetDriveTypeW", return_value=4):
            with patch.object(Path, "lstat", side_effect=AssertionError("traversed mapped drive")):
                with self.assertRaisesRegex(ValueError, "映射"):
                    checked_path(self.backup)

    def test_linked_ancestor_does_not_redirect_private_reads(self):
        import subprocess
        target = self.base / "real"
        target.mkdir()
        (target / "data").write_text("SYNTHETIC", encoding="ascii")
        link = self.base / "alias"
        if os.name == "nt":
            subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                           check=True, capture_output=True)
        else:
            link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "链接|重解析"):
            self.run_action("full", self.selection(backup=str(link / "data")))
        self.assertEqual(self.engine.calls, [])

    def test_stop_before_work_and_log_redaction(self):
        self.flag.set()
        with self.assertRaises(Stopped):
            self.run_action("full")
        self.assertEqual(self.engine.calls, [])
        message = safe_message("Fetched https://user:secret@example.invalid/path?token=secret")
        self.assertNotIn("secret", message)

    def test_window_invalidates_old_results_and_retries_requested_action(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Desktop display unavailable")
        root.withdraw()
        self.addCleanup(root.destroy)
        ui = App(root, self.engine)
        selection = self.selection(target="25.12.2")
        ui.target_mode.set("指定稳定版")
        ui._target_changed()
        for field, value in vars(selection).items():
            if field in ui.values:
                ui.values[field].set(value)
        # Exercise real Tk and task events; no private files or external service.
        ui.detail_dialog = lambda *_args: True

        def wait_for_completion():
            end = time.monotonic() + 8
            while ui.running and time.monotonic() < end:
                root.update()
                time.sleep(.01)
            self.assertFalse(ui.running, "GUI worker did not finish")

        ui.start("full")
        wait_for_completion()
        self.assertEqual(self.engine.calls, ["official"])
        self.assertFalse(ui.results)
        self.assertEqual(ui.official_boot.get(), "32 MiB")
        self.assertEqual(ui.official_root.get(), "300 MiB")
        ui.primary.invoke()
        wait_for_completion()
        self.assertIn("guide", ui.results)
        ui.values["disk_gib"].set("20")
        self.assertEqual(ui.selected_root.get(), "19,967 MiB")
        self.assertFalse(ui.results)
        self.assertEqual(str(ui.guide_btn.cget("state")), "disabled")
        self.assertIn("25.12.2", ui.release.get())
        self.engine.calls.clear()
        with patch.object(self.engine, "build_firmware", side_effect=RuntimeError("fixture failed")):
            ui.start("firmware")
            wait_for_completion()
        self.assertEqual(ui.primary.cget("text"), "重试本次操作")
        ui.primary.invoke()
        wait_for_completion()
        self.assertEqual(self.engine.calls, ["build"])
        self.assertIn("firmware", ui.results)
        self.assertNotIn("recovery", ui.results)
        ui.values["target"].set("25.12.1")
        self.assertIsNone(ui.preview)
        self.assertEqual(ui.official_boot.get(), "—")
        self.assertEqual(ui.primary.cget("text"), "查询版本与分区")
        self.assertFalse(ui.results)

        ui.target_mode.set("离线指定版本")
        self.engine.calls.clear()
        ui.start("firmware")
        wait_for_completion()
        self.assertFalse(self.engine.calls)
        self.assertIsNone(ui.preview.official)
        with patch("gui.messagebox.askyesno", return_value=False) as question:
            ui.primary.invoke()
        self.assertEqual(question.call_args.kwargs["default"], "no")
        self.assertFalse(self.engine.calls)
        with patch("gui.messagebox.askyesno", return_value=True):
            ui.primary.invoke()
            wait_for_completion()
        self.assertEqual(self.engine.layouts[-1], ("build", Layout(20, 512), True))


if __name__ == "__main__":
    unittest.main()
