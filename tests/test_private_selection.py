"""Exercise the archive-selection boundary using in-memory, invented data."""
import io
import struct
import tarfile
import unittest

from engine import private_rules as rules
from fixture_elf import synthetic_core


def selected(overrides):
    m = {p: b"config settings 'main'\n" for p in rules.REQUIRED}
    m["etc/AdGuardHome.yaml"] = b'dns:\n  port: 5335\n'
    m["etc/config/openclash"] = b"config openclash 'config'\n option config_path '/etc/openclash/config/a.yaml'\n"
    m["etc/openclash/config/a.yaml"] = b"rules: []\n"
    m[rules.CORE] = synthetic_core()
    m.update(overrides)
    source = io.BytesIO()
    with tarfile.open(fileobj=source, mode="w") as t:
        for name, value in m.items():
            member = tarfile.TarInfo(name)
            member.mode = 0o777
            if isinstance(value, tuple):
                member.type, member.linkname = value
                t.addfile(member)
            else:
                member.size = len(value)
                t.addfile(member, io.BytesIO(value))
    source.seek(0)
    dest = io.BytesIO()
    notices = set()
    with tarfile.open(fileobj=source, mode="r:") as t, tarfile.open(fileobj=dest, mode="w") as output:
        entries = rules.inventory(t)
        files, links, services = rules.plan(t, entries, set(), notices)
        rules.emit(t, output, files, links, services, {}, [])
    dest.seek(0)
    with tarfile.open(fileobj=dest, mode="r:") as t:
        return {m.name: m for m in t}, notices


class SelectionBoundary(unittest.TestCase):
    def test_local_adh_files_followed_privately(self):
        cfg = b"""dns:
  upstream_dns_file: "/etc/local sources/upstreams"
tls:
  private_key_path: '/etc/personal/cert.key'
filters:
  - url: file:///etc/list.txt
    enabled: true
  - url: https://user:secret@example.invalid/api
"""
        restored, notice = selected({
            "etc/AdGuardHome.yaml": cfg,
            "etc/local sources/upstreams": b"127.0.0.1",
            "etc/personal/cert.key": b"synthetic",
            "etc/list.txt": b"filtered.example",
        })
        for name in ("etc/local sources/upstreams", "etc/personal/cert.key", "etc/list.txt"):
            self.assertIn(name, restored)
        self.assertNotIn("secret", "".join(notice))

    def test_missing_or_external_local_sources_require_review(self):
        cfg = b"""dns:
  upstream_dns_file: /etc/local/missing
tls:
  certificate_path: /mnt/custom/cert.pem
filters:
  - url: file://server.invalid/list
  - url: https://user:secret@example.invalid/api
"""
        _, notices = selected({"etc/AdGuardHome.yaml": cfg})
        review = "\n".join(notices)
        self.assertIn("upstream_dns_file", review)
        self.assertIn("certificate_path", review)
        self.assertIn("filters.url", review)
        self.assertNotIn("secret", review)
        self.assertNotIn("server.invalid", review)

    def test_account_aliases_and_directory_substitution_rejected(self):
        for overrides in (
            {"etc/passwd": (tarfile.SYMTYPE, "/etc/hosts"), "etc/hosts": b"127.0.0.1 router"},
            {"etc/shadow": (tarfile.DIRTYPE, "")},
            {"etc/dnsmasq.d/config": (tarfile.LNKTYPE, "etc/shadow"), "etc/shadow": b"synthetic"},
            {"etc/passwd": (tarfile.LNKTYPE, "etc/hosts"), "etc/hosts": b"synthetic"},
            {"etc/crontabs": (tarfile.SYMTYPE, "/etc/config")},
            {"etc/hosts": (tarfile.DIRTYPE, "")},
        ):
            with self.subTest(paths=list(overrides)), self.assertRaises(rules.LinkIssues):
                selected(overrides)

    def test_core_cannot_point_through_other_archive_domains(self):
        with self.assertRaises(rules.LinkIssues):
            selected({rules.CORE: (tarfile.SYMTYPE, "/etc/openclash/../config/firewall")})

    def test_truncated_or_non_loadable_core_aborts(self):
        good = synthetic_core()
        def changed(offset, form, value):
            damaged = bytearray(good)
            struct.pack_into(form, damaged, offset, value)
            return bytes(damaged)
        examples = {
            "identity-only": good[:64], "short-phdr": good[:100],
            "truncated-segment": good[:-1], "wrong-machine": changed(18, "<H", 183),
            "core-dump": changed(16, "<H", 4), "phdr-outside": changed(32, "<Q", 4096),
            "no-segments": changed(56, "<H", 0), "bad-entry": changed(24, "<Q", 0x402000),
            "no-executable-segment": changed(68, "<I", 4),
            "load-larger-than-memory": changed(104, "<Q", 4),
            "no-load": changed(64, "<I", 0),
        }
        for label, core in examples.items():
            with self.subTest(label=label), self.assertRaisesRegex(rules.Invalid, "OpenClash"):
                selected({rules.CORE: core})
        pie = changed(16, "<H", 3)
        self.assertIn(rules.CORE, selected({rules.CORE: pie})[0])

    def test_inactive_profile_cannot_substitute_for_missing_active_profile(self):
        with self.assertRaises(rules.Invalid):
            selected({"etc/config/openclash": b"config openclash 'config'\n option config_path '/etc/openclash/config/missing.yaml'\n"})

    def test_protected_paths_cannot_reappear_as_implicit_directories(self):
        files, notes = selected({"etc/config/fstab/data": b"old", "etc/shadow": b"synthetic"})
        self.assertNotIn("etc/config/fstab/data", files)
        self.assertIn("跳过 /etc/config/fstab/data", notes)
        for name in ("etc/shadow", "etc/AdGuardHome.yaml"):
            self.assertEqual(files[name].mode, 0o600)
            self.assertEqual(files[name].uid, 0)


if __name__ == "__main__":
    unittest.main()
