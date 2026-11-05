import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import upgrade
from engine.layout import DEFAULT_LAYOUT, Layout


class LayoutWorkflow(unittest.TestCase):
    def test_offline_uses_matching_geometry_and_never_starts_docker(self):
        layout = Layout(15, 768)
        with patch.object(upgrade, "load_verified_firmware", return_value=None) as load, \
                patch.object(upgrade, "import_firmware_bundle", side_effect=AssertionError("wrong bundle")), \
                patch.object(upgrade, "build_local", side_effect=AssertionError("offline docker")):
            with self.assertRaisesRegex(ValueError, "离线"):
                upgrade.build_firmware("25.12.2", "cache", layout=layout, offline=True)
            self.assertEqual(load.call_args.kwargs["layout"], layout)
            load.return_value = {"qcow2": "matching-custom.qcow2"}
            self.assertEqual(upgrade.build_firmware("25.12.2", "cache", layout=layout, offline=True),
                             load.return_value)

    def test_custom_online_build_cannot_substitute_shipped_default(self):
        layout = Layout(20, 768)
        with patch.object(upgrade, "import_firmware_bundle", side_effect=AssertionError("wrong bundle")), \
                patch.object(upgrade, "build_local", return_value={"layout": layout}) as build:
            result = upgrade.build_firmware("25.12.2", "cache", layout=layout)
        self.assertEqual(result["layout"], layout)
        self.assertEqual(build.call_args.kwargs["layout"], layout)

    def test_cli_propagates_same_layout_to_restore_build_and_handoff(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            backup = root / "synthetic.tgz"
            backup.touch()
            args = ["run", "--version", "25.12.2", "--public-dir", str(root / "pub"),
                    "--private-dir", str(root / "private"), "--backup", str(backup)]
            for flags, expected in (([], DEFAULT_LAYOUT), (["--disk-gib", "20", "--boot-mib", "768"], Layout(20, 768))):
                with self.subTest(flags=flags), redirect_stdout(io.StringIO()), \
                        patch.object(upgrade, "prepare_restore", return_value={"raw":"r", "sha256":"s"}) as restore, \
                        patch.object(upgrade, "build_firmware", return_value={"qcow2":"q", "sha256":"h"}) as build, \
                        patch.object(upgrade, "write_guide", return_value="plan") as guide:
                    self.assertEqual(upgrade.main(args + flags), 0)
                    for action in (restore, build, guide):
                        self.assertEqual(action.call_args.kwargs["layout"], expected)

    def test_invalid_size_exits_before_version_lookup_and_build(self):
        with redirect_stderr(io.StringIO()), patch.object(upgrade, "discover_latest", side_effect=AssertionError):
            self.assertEqual(upgrade.main(["build", "--public-dir", "cache", "--disk-gib", "2",
                                          "--boot-mib", "2048"]), 1)

    def test_cli_lookup_only_loads_official_image_if_requested(self):
        with patch.object(upgrade, "discover_latest", return_value="25.12.2"), \
                patch.object(upgrade, "official_layout") as probe:
            with redirect_stdout(io.StringIO()) as result:
                self.assertEqual(upgrade.main(["latest"]), 0)
                self.assertEqual(result.getvalue().strip(), "25.12.2")
            probe.assert_not_called()
            probe.return_value = {"version":"25.12.2", "image_name":"stock.img.gz", "sha256":"f"*64,
                                  "boot_mib":32, "root_mib":300}
            with redirect_stdout(io.StringIO()) as result:
                self.assertEqual(upgrade.main(["latest", "--partitions"]), 0)
                self.assertIn("32 MiB", result.getvalue())
                self.assertIn("300 MiB", result.getvalue())
