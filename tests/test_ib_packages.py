"""Public package verification boundaries, with synthetic local inputs."""
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request


def load(name):
    path = Path(__file__).resolve().parents[1] / "engine" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load("ib-verify-packages")
mirror = load("precache-apk")


class PublicPackagesTest(unittest.TestCase):
    def setUp(self):
        self.manifest = {"luci-app-openclash": "0.48.002", "libfoo3": "1.2-r1", "provider": "2"}
        self.packages = [
            {"name": "luci-app-openclash", "version": "0.48.002"},
            {"name": "libfoo3", "version": "1.2-r1", "tags": ["openwrt:abiversion=3"]},
            {"name": "provider", "version": "2", "provides": ["virtual=1"]},
        ]
        self.requests = {x: x for x in ("luci-app-openclash", "virtual", "libfoo")}

    def test_manifest_matches_actual_packages_with_abi_and_virtuals(self):
        self.assertEqual(verify.verify_packages(self.manifest, self.packages, self.requests), "0.48.002")

    def test_manifest_cannot_substitute_for_final_database_or_change_a_version(self):
        for installed in (self.packages[1:], self.packages + [self.packages[0]],
                          self.packages + [{"name": "phantom", "version": "1"}],
                          self.packages[:2] + [{"name": "provider", "version": "1"}]):
            with self.assertRaises(ValueError):
                verify.verify_packages(self.manifest, installed, self.requests)
        with self.assertRaises(ValueError):
            verify.verify_packages(self.manifest, self.packages, {"missing": "absent"})
        for data in ("foo - 1\nfoo - 1", "stale-name-without-version"):
            with self.assertRaises(ValueError):
                verify.manifest_versions(data)

    def test_mirror_rejects_cross_origin_redirect_even_over_https(self):
        origin = "https://downloads.immortalwrt.org/releases/25.12.2/packages/foo.apk"
        handler = mirror.OfficialRedirect()
        self.assertIsNotNone(handler.redirect_request(Request(origin), None, 302, "", {}, origin))
        for url in ("https://example.invalid/package", "http://downloads.immortalwrt.org/file",
                    "https://downloads.immortalwrt.org@example.invalid/file"):
            with self.assertRaises(ValueError):
                handler.redirect_request(Request(origin), None, 302, "", {}, url)

    def test_streamed_size_limits_apply_with_and_without_content_length(self):
        origin = "https://downloads.immortalwrt.org/releases/25.12.2/packages/file.apk"
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "file.apk"
            dest.write_bytes(b"previous")
            for headers in ({}, {"Content-Length": "12"}):
                response = io.BytesIO(b"too much data")
                response.headers = headers
                response.geturl = lambda: origin
                with patch.object(mirror, "APK_LIMIT", 4), patch.object(mirror.urllib.request, "build_opener") as opener:
                    opener.return_value.open.return_value = response
                    with self.assertRaises(ValueError):
                        mirror.download(origin, dest)
                self.assertEqual(dest.read_bytes(), b"previous")
                self.assertFalse(dest.with_suffix(".apk.part").exists())
