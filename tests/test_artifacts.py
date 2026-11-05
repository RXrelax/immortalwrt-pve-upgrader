import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from engine import artifacts
from engine.layout import DEFAULT_LAYOUT, Layout, SECTOR
from tools.bundle_firmware import package
from upgrade import separate, supported


class PublicCache(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.v = "25.12.2"
        state = str(self.root / "state")
        env = patch.dict(os.environ, {"LOCALAPPDATA": state, "XDG_STATE_HOME": state})
        env.start()
        self.addCleanup(env.stop)
        self.ready = self.make_cache(DEFAULT_LAYOUT, legacy=True)

    def make_cache(self, layout, *, legacy=False):
        directory = self.root / layout.cache_name(self.v)
        directory.mkdir()
        header = bytearray(104)
        header[0:4] = b"QFI\xfb"
        struct.pack_into(">I", header, 4, 3)
        struct.pack_into(">Q", header, 24, layout.disk_bytes)
        binary = bytes(header)
        h = hashlib.sha256(binary).hexdigest()
        man = b"synthetic public manifest"
        geometry = ([(262144, 536870912), (537395200, 15568207872)] if legacy else
                    [(start * SECTOR, length * SECTOR) for start, length in layout.partitions])
        report = dict(release="ImmortalWrt 25.12.2 x86/64", image_bytes=layout.disk_bytes, partition_table="MBR",
                      partitions=[dict(start=x, bytes=y, e2fsck_read_only_exit=0) for x, y in geometry],
                      qcow2_check="passed", qcow2_raw_compare="identical", boot_verified=True,
                      openclash_version="test", adguardhome_keep_checked=True, sha256=h,
                      manifest_sha256=hashlib.sha256(man).hexdigest())
        if not legacy:
            report["layout"] = {"disk_gib": layout.disk_gib, "boot_mib": layout.boot_mib}
        for n, b in zip(artifacts.FILES, (binary, f"{h}  router.qcow2\n".encode(), man, json.dumps(report).encode())):
            (directory / n).write_bytes(b)
        return directory

    def test_cache_tampering_and_boot_marker(self):
        self.assertEqual(artifacts.check(self.ready, self.v)["version"], self.v)
        (self.ready / "router.manifest").write_bytes(b"modified")
        with self.assertRaises(ValueError):
            artifacts.check(self.ready, self.v)

    def test_pinned_zip_only_and_idempotent_import(self):
        bundle = self.root / "download.zip"
        with ZipFile(bundle, "w") as z:
            for file in artifacts.FILES:
                z.write(self.ready / file, file)
        public = self.root / "new"
        with patch.object(artifacts, "ROOT", self.root):
            pins = self.root / "published-bundles.json"
            pins.write_text("{}")
            with self.assertRaises(ValueError):
                artifacts.import_firmware_bundle(bundle, public, lambda s: None)
            self.assertFalse((public / self.ready.name).exists())
            pins.write_text(json.dumps({artifacts.digest(bundle): {"version": self.v,
                "report_sha256": artifacts.digest(self.ready / "verification.json")}}))
            first = artifacts.import_firmware_bundle(bundle, public, lambda s: None)
            again = artifacts.import_firmware_bundle(bundle, public, lambda s: None)
            self.assertEqual(first["sha256"], again["sha256"])

    def test_self_reported_cache_needs_independent_boot_or_release_record(self):
        result = artifacts.check(self.ready, self.v)
        with self.assertRaisesRegex(ValueError, "冷启动记录"):
            artifacts.load_verified_firmware(self.v, self.root)
        artifacts.remember_boot_test(result)
        self.assertEqual(artifacts.load_verified_firmware(self.v, self.root)["layout"], {"disk_gib": 15, "boot_mib": 512})
        receipt = artifacts.receipt_path(result)
        self.assertEqual(receipt.name, result["report_sha256"])
        self.assertEqual(receipt.parent.name, "verified-builds")
        receipt.write_text(f"{self.v} {result['sha256']}\n", encoding="ascii")
        self.assertEqual(artifacts.load_verified_firmware(self.v, self.root)["sha256"], result["sha256"])

    def test_wrong_layout_in_cache_or_report(self):
        layout = Layout(15, 256)
        self.assertIsNone(artifacts.load_verified_firmware(self.v, self.root, layout=layout))
        directory = self.make_cache(layout)
        report = directory / "verification.json"
        data = json.loads(report.read_bytes())
        for fields in (None, {"disk_gib": 15, "boot_mib": 512}, {"disk_gib": 15, "boot_mib": 256.0}):
            with self.subTest(fields=fields):
                if fields is None:
                    data.pop("layout")
                else:
                    data["layout"] = fields
                report.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "分区结构"):
                    artifacts.check(directory, self.v, layout)
        # A swapped-in default cache has the same virtual size. Even a relabelled
        # report still has to match every partition offset and length.
        shutil.copytree(self.ready, directory, dirs_exist_ok=True)
        data = json.loads(report.read_bytes())
        data["layout"] = {"disk_gib": 15, "boot_mib": 256}
        report.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "分区结构"):
            artifacts.load_verified_firmware(self.v, self.root, layout=layout)

    def test_custom_virtual_size_and_version(self):
        layout = Layout(16, 512)
        directory = self.make_cache(layout)
        self.assertEqual(artifacts.check(directory, self.v, layout)["layout"], {"disk_gib": 16, "boot_mib": 512})
        with self.assertRaisesRegex(ValueError, "版本"):
            artifacts.check(directory, "25.12.3", layout)
        shutil.copyfile(self.ready / "router.qcow2", directory / "router.qcow2")
        with self.assertRaisesRegex(ValueError, "16 GiB QCOW2"):
            artifacts.check(directory, self.v, layout)

    def test_custom_receipt_bound_to_layout_and_report(self):
        layout = Layout(15, 256)
        custom = artifacts.check(self.make_cache(layout), self.v, layout)
        original = artifacts.check(self.ready, self.v)
        artifacts.remember_boot_test(original)
        custom_receipt = artifacts.receipt_path(custom)
        self.assertNotEqual(custom_receipt.parent, artifacts.receipt_path(original).parent)
        custom_receipt.parent.mkdir(parents=True)
        # Use identical synthetic QCOW bytes to exercise the report/receipt binding.
        self.assertEqual(custom["sha256"], original["sha256"])
        pins = {"legacy": {"version": self.v, "report_sha256": custom["report_sha256"]}}
        with patch.object(artifacts, "release_pins", return_value=pins):
            for wrong in (artifacts.receipt_path(original).read_text("ascii"), f"{self.v} {original['sha256']}\n"):
                custom_receipt.write_text(wrong, encoding="ascii")
                with self.assertRaisesRegex(ValueError, "冷启动记录"):
                    artifacts.load_verified_firmware(self.v, self.root, layout=layout)
        artifacts.remember_boot_test(custom)
        self.assertEqual(artifacts.load_verified_firmware(self.v, self.root, layout=layout), custom)
        with custom["verification"].open("ab") as report:
            report.write(b"\n")
        with self.assertRaisesRegex(ValueError, "冷启动记录"):
            artifacts.load_verified_firmware(self.v, self.root, layout=layout)

    def test_release_zip_and_packaging_are_default_layout_only(self):
        layout = Layout(15, 256)
        custom = artifacts.check(self.make_cache(layout), self.v, layout)
        artifacts.remember_boot_test(custom)
        self.ready.rename(self.root / "old-default")
        with self.assertRaisesRegex(ValueError, "默认布局"):
            package(self.v, self.root, self.root / "bundles")
        public = self.root / "import"
        with self.assertRaisesRegex(ValueError, "默认分区布局"):
            artifacts.import_firmware_bundle(self.root / "release.zip", public, layout=layout)
        self.assertFalse(public.exists())

    def test_packaged_new_default_report_imports_with_recorded_layout(self):
        new_layout = {"disk_gib": 15, "boot_mib": 512}
        report = self.ready / "verification.json"
        data = json.loads(report.read_bytes())
        data["layout"] = new_layout
        report.write_text(json.dumps(data), encoding="utf-8")
        verified = artifacts.check(self.ready, self.v)
        artifacts.remember_boot_test(verified)
        pin_dir = self.root / "engine"
        pin_dir.mkdir()
        pins = pin_dir / "published-bundles.json"
        pins.write_text("{}", encoding="utf-8")
        with patch("tools.bundle_firmware.APP", self.root), patch.object(artifacts, "ROOT", pin_dir):
            package(self.v, self.root, self.root / "bundles", record=True)
            bundle = self.root / "bundles" / f"RouterUpgrade-firmware-{self.v}.zip"
            self.assertEqual(json.loads(pins.read_bytes())[artifacts.digest(bundle)]["layout"], new_layout)
            imported = artifacts.import_firmware_bundle(bundle, self.root / "new-public")
            self.assertEqual(imported["report_sha256"], verified["report_sha256"])
            self.assertEqual(imported["layout"], new_layout)

    def test_pinned_import_does_not_return_another_legitimate_same_version_build(self):
        zfile = self.root / "download.zip"
        with ZipFile(zfile, "w") as z:
            for name in artifacts.FILES:
                z.write(self.ready / name, name)
        original = artifacts.digest(self.ready / "verification.json")
        with (self.ready / "verification.json").open("a") as f:
            f.write("\n")
        other = artifacts.digest(self.ready / "verification.json")
        pins = {artifacts.digest(zfile): {"version": self.v, "report_sha256": original},
                "test-other": {"version": self.v, "report_sha256": other}}
        with patch.object(artifacts, "release_pins", return_value=pins):
            with self.assertRaisesRegex(ValueError, "不同构建"):
                artifacts.import_firmware_bundle(zfile, self.root, lambda _: None)

    def test_release_gate_and_path_boundaries(self):
        self.assertEqual(supported(self.v), self.v)
        for v in ("25.12-SNAPSHOT", "26.1.0", "../25.12.2"):
            with self.assertRaises(ValueError):
                supported(v)
        with self.assertRaises(ValueError):
            separate(self.root, self.root / "subfolder", self.ready / "backup")
