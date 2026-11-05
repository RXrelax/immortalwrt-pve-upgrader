from html.parser import HTMLParser
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from engine.handoff import write_guide
from engine.layout import Layout


class GuideLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.anchors = set()
        self.refs = []
        self.external = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.anchors.add(attrs["id"])
        if tag == "a":
            self.refs.append(attrs["href"])
        if any(name in attrs for name in ("src", "data", "srcset")) or tag in ("script", "link", "iframe"):
            self.external.append(tag)


class GuideTest(unittest.TestCase):
    def test_complete_offline_guide_does_not_disclose_private_metadata(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            version = "25.12.2"
            public_hash = "a" * 64
            private_hash = "b" * 64
            home = Path(tmp) / "PERSONAL-NAME"
            firmware = {"version": version, "sha256": public_hash, "qcow2": home / 'DoNotEmbed.qcow2'}
            recovery = {"sha256": private_hash, "archive": home / "secret.tgz", "raw": home / "sensitive.raw"}
            stored = write_guide(version, Path(tmp), firmware, recovery)
            page = stored.read_text("utf-8")
            self.assertIn(version, page)
            self.assertIn(public_hash, page)
            self.assertIn("immortalwrt-25.12.2-aaaaaaaaaaaa.qcow2", page)
            for secret in (private_hash, "PERSONAL-NAME", "DoNotEmbed", "secret.tgz", "sensitive.raw", "{{"):
                self.assertNotIn(secret, page)
            parser = GuideLinks()
            parser.feed(page)
            self.assertGreaterEqual(len(parser.refs), 8)
            self.assertIn("IMWRT-RESTORE-V2", page)
            self.assertIn("RUN_READY", page)
            self.assertTrue(all(ref[0] == "#" and ref[1:] in parser.anchors for ref in parser.refs))
            self.assertEqual(parser.external, [])
            for term in ("15 GiB", "512 MiB", "14,847", "Detach",
                         "RUN.SH", "RESTORE.ID", "RESTORE_OK", "pve-stage.sh", "回退"):
                self.assertIn(term, page)
            second = write_guide(version, Path(tmp), firmware, recovery)
            self.assertNotEqual(second, stored)
            self.assertEqual(stored.read_bytes(), second.read_bytes())

    def test_incomplete_job_is_described_as_incomplete(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            page = write_guide("25.12.2", Path(tmp), None, None).read_text("utf-8")
            self.assertIn("尚未验证系统盘", page)
            self.assertIn("尚未准备私有恢复盘", page)

    def test_mismatched_version_or_digest_does_not_create_file(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            for v, result in (("25.12.2", {"version":"25.12.1", "sha256":"a"*64}),
                              ("25.12.2", {"version":"25.12.2", "sha256":"<bad>"}),
                              ("../../injected", None)):
                with self.subTest(version=v, data=result), self.assertRaises(ValueError):
                    write_guide(v, Path(tmp), result, None)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_selected_geometry_and_marker_in_every_step(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            layout = Layout(20, 768)
            public = {"version": "25.12.2", "sha256": "a" * 64,
                      "layout": {"disk_gib": 20, "boot_mib": 768}}
            private = {"version": public["version"], "layout": public["layout"]}
            guide = write_guide(public["version"], Path(tmp), public, private, layout)
            page = guide.read_text("utf-8")
            for expected in ("20 GiB", "768 MiB", "19,711 MiB", "= 'IMWRT-RESTORE-V3 20 768'"):
                self.assertIn(expected, page)
            for stale in ("15 GiB", "512 MiB", "14,847", "14.5 GiB", "IMWRT-RESTORE-V2", "{{"):
                self.assertNotIn(stale, page)

    def test_wrong_geometry_or_recovery_version_aborts_before_writing(self):
        with TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            requested = Layout(20, 768)
            mismatched = {"version": "25.12.2", "layout": {"disk_gib": 20, "boot_mib": 512}}
            legacy = {"version": "25.12.2", "sha256": "a" * 64}
            wrong_version = {"version": "25.12.1", "layout": {"disk_gib": 20, "boot_mib": 768}}
            for firmware, recovery in ((legacy, None), (None, legacy), (None, mismatched),
                                       (mismatched, None), (None, wrong_version)):
                with self.subTest(firmware=firmware, recovery=recovery), self.assertRaises(ValueError):
                    write_guide("25.12.2", Path(tmp), firmware, recovery, requested)
            self.assertEqual(list(Path(tmp).iterdir()), [])
