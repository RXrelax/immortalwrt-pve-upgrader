"""Offline regression tests. Inputs are synthesized; no real backups are opened."""
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.layout import DEFAULT_LAYOUT, Layout
from engine.private_restore import PrivateError, prepare_private
from fixture_elf import synthetic_core


CORE = "etc/openclash/core/clash_meta"
FILT = "usr/bin/AdGuardHome/data/filters/"
ARGON = "www/luci-static/argon/background/"
PROFILE = "etc/openclash/config/my local name.yaml"
PRIVATE = b"test-only-private-value"


def firmware_config():
    members = {f"etc/config/{name}": b"config settings 'main'\n" for name in
               ("network", "firewall", "dhcp", "dropbear")}
    members.update({
        CORE: synthetic_core(),
        PROFILE: b"rules: []\n",
        "etc/config/openclash": f"config openclash 'config'\n option config_path '/{PROFILE}'\n".encode(),
        "etc/AdGuardHome.yaml": b"filters:\n  - enabled: true\n    id: 123\n",
        "etc/shadow": PRIVATE,
        "etc/config/argon": b"config argon\n",
        "etc/config/luci_statistics": b"config statistics 'collectd'\n",
        "etc/collectd.conf": "/var/etc/collectd.conf",
        ARGON + "image with spaces.jpg": b"\xff\xd8\xff synthetic image",
        FILT + "123.txt": b"||example.invalid^\n",
        "etc/config/fstab": b"config mount\n",
        "etc/apk/keys/old-key.pem": b"old repository key",
    })
    return members


class LocalRestore(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dest = self.root / "private-out"
        self.dest.mkdir()
        self.source = self.root / "local-backup.tar.gz"
        self.logs, self.notices = [], []

    def write(self, members):
        with tarfile.open(self.source, "w:gz") as t:
            for name, data in members.items():
                m = tarfile.TarInfo("./" + name)
                m.mode = 0o755 if name == CORE else 0o600
                if isinstance(data, str):
                    m.type, m.linkname = tarfile.SYMTYPE, data
                    t.addfile(m)
                else:
                    m.size = len(data)
                    t.addfile(m, io.BytesIO(data))

    def prepare(self, members, filters=None, yes=True, version="25.12.2", layout=DEFAULT_LAYOUT):
        self.write(members)
        def review(items):
            self.notices.extend(items)
            return yes
        return prepare_private(self.source, self.dest, version, filters, review, self.logs.append, layout)

    def test_roundtrip_prefers_in_archive_and_supplements_missing_sets(self):
        members = firmware_config()
        folder = self.root / "filters"
        folder.mkdir()
        (folder/"123.txt").write_bytes(b"stale copy")
        (folder/"2.txt").write_bytes(b"external filter")
        out = self.prepare(members, folder)
        self.assertEqual(out["filter_count"], 2)
        self.assertEqual(out["sha256"], hashlib.sha256(out["raw"].read_bytes()).hexdigest())
        with tarfile.open(out["raw"]) as raw:
            self.assertEqual(raw.getnames(), ["RESTORE.ID", "SHA256SUM", "RESTORE.TGZ", "RUN.SH"])
            self.assertEqual(raw.extractfile("RESTORE.ID").read(), b"IMWRT-RESTORE-V2\n")
            inner = raw.extractfile("RESTORE.TGZ").read()
            self.assertEqual(inner, out["archive"].read_bytes())
            self.assertEqual(raw.extractfile("SHA256SUM").read(),
                             (hashlib.sha256(inner).hexdigest() + "  RESTORE.TGZ\n").encode())
            script = raw.extractfile("RUN.SH").read()
            self.assertIn(b"DISTRIB_RELEASE='25.12.2'", script)
            self.assertNotIn(b"24.10.6", script)
            for check in (b"31457280",b"1048576",b"1049600",b"30406656",b"mountinfo",b"RESTORE_OK"):
                self.assertIn(check,script)
        with tarfile.open(out["archive"]) as t:
            self.assertEqual(t.extractfile(FILT+"123.txt").read(),members[FILT+"123.txt"])
            self.assertEqual(t.extractfile(FILT+"2.txt").read(),b"external filter")
            self.assertIn(ARGON+"image with spaces.jpg",t.getnames())
            self.assertIn("etc/config/argon", t.getnames())
            self.assertNotIn("etc/apk/keys/old-key.pem",t.getnames())
            self.assertNotIn("etc/config/fstab",t.getnames())
            self.assertNotIn("etc/collectd.conf",t.getnames())
            self.assertIn("etc/config/luci_statistics",t.getnames())
        for private in (str(self.root), PROFILE, PRIVATE.decode(), "image with spaces"):
            self.assertNotIn(private,"\n".join(self.logs))

    def test_no_cached_filters_requires_review_even_with_no_other_omissions(self):
        members = firmware_config()
        for n in ("etc/collectd.conf", "etc/config/fstab", "etc/apk/keys/old-key.pem", FILT+"123.txt"):
            del members[n]
        with self.assertRaises(PrivateError):
            self.prepare(members,yes=False)
        self.assertFalse(list(self.dest.iterdir()))
        self.assertTrue(any("过滤缓存" in x for x in self.notices))
        out=self.prepare(members)
        self.assertEqual(out["filter_count"],0)

    def test_same_release_has_distinct_custom_carrier_and_marker(self):
        selected = Layout(20, 768)
        old = self.prepare(firmware_config())
        custom = self.prepare(firmware_config(), layout=selected)
        self.assertEqual(custom["version"], old["version"])
        self.assertEqual(custom["layout"], {"disk_gib": 20, "boot_mib": 768})
        self.assertNotEqual(custom["sha256"], old["sha256"])
        with tarfile.open(custom["raw"]) as raw:
            self.assertEqual(raw.extractfile("RESTORE.ID").read(), b"IMWRT-RESTORE-V3 20 768\n")
            script = raw.extractfile("RUN.SH").read()
            self.assertIn(b"= 'IMWRT-RESTORE-V3 20 768'", script)
            for value in (selected.disk_bytes // 512, *selected.partitions[0], *selected.partitions[1]):
                self.assertIn(f"= {value} ]".encode(), script)
            self.assertNotRegex(script, rb"@[A-Z_]+@")

    @unittest.skipUnless(shutil.which("sh"), "requires a POSIX shell")
    def test_rendered_guest_guard_rejects_wrong_boot_even_when_disk_size_matches(self):
        layout = Layout(20, 768)
        custom = self.prepare(firmware_config(), layout=layout)
        with tarfile.open(custom["raw"]) as raw:
            script = raw.extractfile("RUN.SH").read().decode("ascii")
        guard = script[script.index('[ "${rootpart##*/}"'):script.index("disk=''")]
        disk = self.root / "sda"
        boot, root = disk / "sda1", disk / "sda2"
        boot.mkdir(parents=True)
        root.mkdir()
        (disk / "size").write_text(str(layout.disk_bytes // 512))
        (disk / "ro").write_text("0")
        for part, (start, size) in zip((boot, root), layout.partitions):
            (part / "start").write_text(str(start))
            (part / "size").write_text(str(size))
        shell = 'fail() { exit 1; }; base=sda; rootpart=sda/sda2; rootbase=sda\n' + guard
        for actual_boot, expected in ((layout.boot_mib, 0), (512, 1)):
            (boot / "size").write_text(str(actual_boot * 2048))
            check = subprocess.run(["sh", "-c", shell], cwd=self.root, capture_output=True)
            self.assertEqual(check.returncode, expected, check.stderr)

    def test_first_run_creates_missing_private_directory(self):
        self.dest = self.root/"new-private"/"exports"
        out = self.prepare(firmware_config())
        self.assertTrue(out["raw"].is_file())
        self.assertTrue(out["raw"].is_relative_to(self.dest))

    def test_missing_enabled_filter_is_reviewed_despite_other_cached_files(self):
        members = firmware_config()
        members["etc/AdGuardHome.yaml"] += b"  - enabled: true\n    id: 555\n"
        with self.assertRaises(PrivateError): self.prepare(members,yes=False)
        self.assertTrue(any("1 项已启用" in s for s in self.notices))

    def test_missing_mandatory_core_or_profile_aborts(self):
        for name in (CORE, PROFILE, "etc/config/firewall", "etc/AdGuardHome.yaml"):
            with self.subTest(name=name):
                m=firmware_config()
                del m[name]
                with self.assertRaises(PrivateError): self.prepare(m)
                self.assertFalse(list(self.dest.iterdir()))

    def test_refuses_private_web_alias_and_traversal(self):
        for name, data in ((ARGON+"private.jpg", "/etc/shadow"),
                           ("etc/openclash/../etc/init.d/bad", b"unsafe"),
                           (FILT+"extra.txt","/etc/shadow")):
            with self.subTest(name=name):
                with self.assertRaises(PrivateError): self.prepare({**firmware_config(),name:data})
                self.assertFalse(list(self.dest.iterdir()))

    def test_never_replays_arbitrary_service_commands(self):
        members = firmware_config()
        members["etc/uci-defaults/10_disable_services"] = b"/etc/init.d/sqm disable; echo bad\nexit 0\n"
        with self.assertRaises(PrivateError): self.prepare(members)
        self.assertFalse(list(self.dest.iterdir()))

    def test_no_partial_artifact_when_carrier_fails(self):
        with patch("engine.private_restore.create_carrier",side_effect=OSError("synthetic failure")):
            with self.assertRaises(PrivateError): self.prepare(firmware_config())
        self.assertFalse(list(self.dest.iterdir()))

    def test_backup_changed_during_user_review_is_not_published(self):
        self.write(firmware_config())
        def changed(_items):
            metadata = self.source.stat()
            os.utime(self.source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 2_000_000_000))
            return True
        with self.assertRaises(PrivateError):
            prepare_private(self.source, self.dest, "25.12.2", None, changed, self.logs.append)
        self.assertFalse(list(self.dest.iterdir()))

    def test_rejects_bad_version_and_source_crc(self):
        with self.assertRaises(ValueError): self.prepare(firmware_config(),version="25.12.2'\nSH")
        self.write(firmware_config())
        data=bytearray(self.source.read_bytes())
        data[-8] ^= 1
        self.source.write_bytes(data)
        with self.assertRaises(PrivateError):
            prepare_private(self.source,self.dest,"25.12.2",None,lambda _:True,self.logs.append)
        self.assertFalse(list(self.dest.iterdir()))

    def test_cannot_export_to_a_git_checkout_or_sync_root(self):
        self.write(firmware_config())
        for folder in (self.root/"OneDrive - Test", self.root/"repo"):
            folder.mkdir()
            if folder.name=="repo": (folder/".git").mkdir()
            with self.assertRaises(PrivateError):
                prepare_private(self.source,folder,"25.12.2",None,lambda _:True,self.logs.append)


if __name__ == "__main__":
    unittest.main()
