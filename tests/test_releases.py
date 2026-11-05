"""Public synthetic fixtures for the update wizard's release trust boundary."""
import base64
import gzip
from hashlib import sha256
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))
import releases


class ReleasesTest(unittest.TestCase):
    def test_latest_by_number_excludes_rc_snapshot_and_foreign_urls(self):
        links = ("25.12.9/", "25.12.10/", "26.01-SNAPSHOT/", "25.12.11-rc1/",
                 "26.01.0/", "packages-25.12.20/", "https://example.invalid/27.1.0/")
        html = "".join(f'<a href="{item}">Build</a>' for item in links).encode()
        with patch.object(releases, "_public_bytes", return_value=html):
            self.assertEqual(releases.discover(), "26.01.0")
        with patch.object(releases, "_public_bytes", return_value=html.replace(b"26.01.0/", b"26.01.0-rc2/")):
            self.assertEqual(releases.discover(), "25.12.10")

    def test_unsupported_series_and_bad_strings_never_use_network(self):
        for version in ("25.12.2-rc1", "26.1.0", "25.12.2/../xx", "24.10.6"):
            with self.subTest(version=version), patch.object(releases, "_public_bytes", side_effect=AssertionError):
                with self.assertRaises(releases.ReleaseError):
                    releases.prepare_inputs(version, ".", lambda line: None)

    def test_private_or_plaintext_redirects_disallowed(self):
        for url in ("http://downloads.immortalwrt.org/", "https://127.0.0.1/",
                    "https://github.com:8443/pkg", "https://key@github.com/pkg", "file:///C:/one.txt"):
            with self.subTest(url=url), self.assertRaises(releases.ReleaseError):
                releases._check_url(url)

    def test_manifest_path_and_duplicates(self):
        digest = b"e" * 64
        name = "asset.tar.zst"
        correct = digest + b" *" + name.encode() + b"\n"
        self.assertEqual(releases._signed_digest(correct, name), digest.decode())
        for invalid in (correct * 2, correct.replace(b"asset", b"./asset"), correct.replace(b"asset", b"asset-extra")):
            with self.assertRaises(releases.ReleaseError):
                releases._signed_digest(invalid, name)

    def test_copied_artifacts_are_revalidated_offline(self):
        version = "25.12.2"
        builder, core = b"public test builder", b"public test core"
        metadata = (sha256(builder).hexdigest() +
                    f" *immortalwrt-imagebuilder-{version}-x86-64.Linux-x86_64.tar.zst\n").encode()
        signature = b"test detached signature"
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            originals = {"imagebuilder.tar.zst": builder, "AdGuardHome.tar.gz": core,
                         "sha256sums": metadata, "sha256sums.sig": signature}
            for name, content in originals.items():
                (folder / name).write_bytes(content)
            def verify(data, sig, key):
                if (data, sig, key) != (metadata, signature, releases.RELEASE_KEYS[(25, 12)]):
                    raise releases.ReleaseError("Unexpected metadata")
            with patch.object(releases, "_verify_signature", side_effect=verify), \
                    patch.object(releases, "ADH_SIZE", len(core)), \
                    patch.object(releases, "ADH_SHA256", sha256(core).hexdigest()), \
                    patch.object(releases, "_public_bytes", side_effect=AssertionError):
                releases.verify_staged_inputs(version, folder)
                for name, content in originals.items():
                    with self.subTest(name=name):
                        (folder / name).write_bytes(b"X" + content[1:])
                        with self.assertRaises(releases.ReleaseError):
                            releases.verify_staged_inputs(version, folder)
                        (folder / name).write_bytes(content)

    def test_ed25519_positive_and_tamper(self):
        # RFC 8032 §7.1, test 2. This also tests OpenSSL-only installations.
        binary_key = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        signature = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                                  "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
        tag = b"Ed12345678"
        message = b"\x72"
        public = base64.b64encode(tag + binary_key)
        sig = b"untrusted comment: test\n" + base64.b64encode(tag + signature) + b"\n"
        releases._verify_signature(message, sig, public)
        for m, s, k in ((message+b"!", sig, public), (message, b"damaged", public),
                        (message, sig, base64.b64encode(b"Ed87654321"+binary_key))):
            with self.assertRaises(releases.ReleaseError):
                releases._verify_signature(m, s, k)

    def test_never_publish_failed_download_and_reuse_good_cache(self):
        data=b"official synthetic artifact"
        digest=sha256(data).hexdigest()
        def write_data(url, f, limit):
            f.write(data)
            return len(data), digest
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder:
            dest=Path(folder)/"test.tar.gz"
            with patch.object(releases, "_fetch", side_effect=write_data):
                with self.assertRaises(releases.ReleaseError):
                    releases._asset("unused", dest, "0"*64, 100, lambda line: None)
                self.assertEqual(list(Path(folder).iterdir()), [])
                releases._asset("unused", dest, digest, 100, lambda line: None, len(data))
            with patch.object(releases, "_fetch", side_effect=AssertionError):
                releases._asset("unused", dest, digest, 100, lambda line: None)
            self.assertEqual(dest.read_bytes(), data)


class OfficialLayoutTest(unittest.TestCase):
    version = "25.12.10"
    name = f"immortalwrt-{version}-x86-64-generic-ext4-combined.img.gz"

    def mbr(self):
        table = bytearray(512)
        table[0] = 0xeb
        table[510:] = b"\x55\xaa"
        for slot, (flag, start, length) in enumerate(((0x80, 512, 65536), (0, 66560, 4097))):
            struct.pack_into("<B3xB3xII", table, 446 + slot * 16, flag, 0x83, start, length)
        return table

    def test_exact_release_signature_and_whole_asset_hash_before_reading_mbr(self):
        # Official images can carry fwtool data after the disk's gzip member.
        image = gzip.compress(self.mbr()) + b"public firmware footer"
        digest = sha256(image).hexdigest()
        sums = f"{digest} *{self.name}\n".encode()
        base = f"{releases.ROOT}{self.version}/targets/x86/64/"
        assets = {base + "sha256sums": sums, base + "sha256sums.sig": b"signature", base + self.name: image}

        def fetch(url, out, limit):
            data = assets[url]
            self.assertLessEqual(len(data), limit)
            out.write(data)
            return len(data), sha256(data).hexdigest()

        with patch.object(releases, "_fetch", side_effect=fetch), patch.object(releases, "_verify_signature") as verify:
            layout = releases.official_layout(self.version, log=None)
            verify.assert_called_once_with(sums, b"signature", releases.RELEASE_KEYS[(25, 12)])
            self.assertEqual(layout, {"version": self.version, "image_name": self.name, "sha256": digest,
                                      "boot_mib": 32, "root_mib": 4097 / 2048,
                                      "partitions": [{"start": 512 * 512, "bytes": 65536 * 512},
                                                     {"start": 66560 * 512, "bytes": 4097 * 512}]})
            assets[base + self.name] += b"!"
            with patch.object(releases, "_official_mbr", side_effect=AssertionError), \
                    self.assertRaisesRegex(releases.ReleaseError, "SHA-256"):
                releases.official_layout(self.version, log=None)

    def test_missing_key_bad_signature_and_efi_only_fail_before_image_download(self):
        with patch.object(releases, "_public_bytes", side_effect=AssertionError), \
                self.assertRaisesRegex(releases.ReleaseError, "可信发布公钥"):
            releases.official_layout("26.1.0", log=None)
        wrong_name = self.name.replace("combined.img", "combined-efi.img")
        sums = ("f" * 64 + " *" + wrong_name + "\n").encode()
        with patch.object(releases, "_public_bytes", return_value=sums), \
                patch.object(releases, "_fetch", side_effect=AssertionError):
            with self.assertRaisesRegex(releases.ReleaseError, "签名"):
                releases.official_layout(self.version, log=None)
            with patch.object(releases, "_verify_signature"), self.assertRaisesRegex(releases.ReleaseError, "记录"):
                releases.official_layout(self.version, log=None)

    def test_rejects_unrecognized_or_overlapping_partitions(self):
        for offset, change in ((510, b"\0"), (446, b"\0"), (450, b"\xee"), (478, b"\x80"),
                               (470, struct.pack("<I", 66047)), (474, b"\xff" * 4), (458, b"\0" * 4)):
            table = self.mbr()
            table[offset:offset + len(change)] = change
            with self.subTest(offset=offset), self.assertRaises(releases.ReleaseError):
                releases._official_mbr(io.BytesIO(gzip.compress(table)))
        for invalid in (b"", b"bad gzip", gzip.compress(b"x" * 511)):
            with self.subTest(invalid=invalid), self.assertRaises(releases.ReleaseError):
                releases._official_mbr(io.BytesIO(invalid))


if __name__ == "__main__":
    unittest.main()
