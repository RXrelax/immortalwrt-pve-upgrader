import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from engine.dockerbuild import build_firmware, certify, copy_build_code, local_docker
from engine.layout import Layout


class LocalBuildTransport(unittest.TestCase):
    def test_remote_transport_stops_before_daemon_use(self):
        for host in ("ssh://remote", "tcp://somewhere:2376", "npipe:////server/pipe/docker_engine", "unix:////server/share"):
            with self.subTest(host=host), patch.dict(os.environ, {"DOCKER_HOST":host,"DOCKER_CONTEXT":""}), \
                    patch("engine.dockerbuild.run") as cli:
                with self.assertRaisesRegex(RuntimeError,"远程"):
                    local_docker(print)
                cli.assert_not_called()

    def test_explicit_context_takes_precedence_and_pins_local_endpoint(self):
        endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine"
        with patch.dict(os.environ, {"DOCKER_HOST":"ssh://unused", "DOCKER_CONTEXT":"desktop-linux"}), \
                patch("engine.dockerbuild.run", side_effect=["desktop-linux",endpoint]) as cli:
            self.assertEqual(local_docker(print),["docker","--host",endpoint])
            self.assertEqual(cli.call_count,2)

    def test_custom_layout_cache_is_selected_before_contacting_docker(self):
        layout = Layout(20, 768)
        with tempfile.TemporaryDirectory() as directory, \
                patch("engine.dockerbuild.load_verified_firmware", return_value={"qcow2": "cached"}) as cached, \
                patch("engine.dockerbuild.local_docker") as docker:
            root = Path(directory)
            self.assertEqual(build_firmware("25.12.2", root, layout=layout), {"qcow2": "cached"})
            cached.assert_called_once_with("25.12.2", root, log=print, layout=layout)
            docker.assert_not_called()

    def test_container_tools_include_the_shared_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "engine"
            copy_build_code(stage)
            self.assertTrue((stage / "layout.py").is_file())

    def test_custom_layout_is_passed_to_guest_and_report_validation(self):
        layout = Layout(20, 768)
        with tempfile.TemporaryDirectory() as directory, patch("engine.dockerbuild.run", return_value="PASS:") as run, \
                patch("engine.dockerbuild.check") as check:
            stage = Path(directory)
            (stage / "verification.json").write_text("{}", encoding="utf-8")
            certify(stage, "25.12.2", "seabios", print, ["docker"], layout)
            command = run.call_args.args[0]
            self.assertEqual(command[-4:], ["--disk-gib", "20", "--boot-mib", "768"])
            self.assertIn("target=/layout.py,readonly", " ".join(command))
            check.assert_called_once_with(stage, "25.12.2", layout=layout)
