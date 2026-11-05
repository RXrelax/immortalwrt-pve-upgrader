"""PVE disk staging tests. The only source images are generated test headers."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
script = (ROOT / "engine/pve-stage.sh").read_text(encoding="utf-8")
code = script.split("<<'ROUTER_UPGRADE_PY'\n", 1)[1].rsplit("\nROUTER_UPGRADE_PY", 1)[0]
stage = {"__name__": "pve_stage"}
exec(compile(code, "pve-stage.sh", "exec"), stage)
Stop = stage["Stop"]
native_lock = stage["stage_lock"]
native_read_mbr = stage["read_mbr"]
MIB = stage["MIB"]
GIB = 1024 * MIB
linux_qemu = unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0 and shutil.which("qemu-img"),
                                 "requires Linux root and qemu-img for the isolated fake node")


def fixture_mbr(disk_gib, boot_mib):
    mbr = bytearray(512)
    mbr[0], mbr[510:] = 0xeb, b"\x55\xaa"
    struct.pack_into("<B3xB3xII", mbr, 446, 0x80, 0x83, 512, boot_mib * 2048)
    root_mib = disk_gib * 1024 - boot_mib - 1
    struct.pack_into("<B3xB3xII", mbr, 462, 0, 0x83, boot_mib * 2048 + 1024, root_mib * 2048)
    return mbr


def fixture_read_mbr(source):
    source.seek(2048)
    return source.read(512)


class StubPVE:
    def __init__(self, directory):
        self.directory = directory
        self.cfg = {"digest": "a" * 40, "scsihw": "virtio-scsi-single",
                    "scsi0": "local-lvm:vm-100-disk-0,size=336M",
                    "scsi1": "local-lvm:vm-100-disk-1,size=10G", "boot": "order=scsi0"}
        self.pending = []
        self.status = "stopped"
        self.ha_managed = 0
        self.available = 30 * GIB
        self.storage_config = {"storage": "local-lvm", "type": "lvmthin", "vgname": "pve-qa", "thinpool": "data"}
        self.extent = 4 * MIB
        self.vg_report = None
        self.sets = []
        self.simulate = ""

    def __call__(self, *cmd):
        if cmd[:2] == ("pvesm", "path"):
            return str(self.directory / cmd[2].split("/")[-1])
        if cmd[0] == "vgs":
            assert cmd[1:] == ("--reportformat", "json", "--units", "b", "--nosuffix",
                               "-o", "vg_extent_size,vg_name", self.storage_config["vgname"])
            if self.vg_report is not None:
                return json.dumps(self.vg_report)
            return json.dumps({"report": [{"vg": [{"vg_name": self.storage_config["vgname"],
                                                  "vg_extent_size": f"{self.extent}.00"}]}]})
        if cmd[:2] == ("pvesh", "get"):
            path = cmd[2]
            if path == "/storage/local-lvm":
                return json.dumps(self.storage_config)
            if path.endswith("/config"):
                return json.dumps(self.cfg)
            if path.endswith("/pending"):
                return json.dumps(self.pending)
            if path.endswith("/current"):
                return json.dumps({"status": self.status, "ha": {"managed": self.ha_managed}})
            if path.endswith("/status"):
                return json.dumps({"type": "lvmthin", "enabled": 1, "active": 1,
                                   "content": "images,rootdir", "avail": self.available})
        if cmd[:3] == ("qm", "set", "100"):
            assert cmd[3] == "--digest" and cmd[4] == self.cfg["digest"]
            slot, disk = cmd[5][2:], cmd[6]
            assert slot not in self.cfg
            self.sets.append(slot)
            if self.simulate == "ambiguous-empty" and len(self.sets) == 2:
                raise Stop("interrupted")
            opts = disk.split(",")[2:]
            if "ro=1" in opts:
                raw_size = (self.directory / "restore.raw").stat().st_size
                lv_bytes = ((raw_size + self.extent - 1) // self.extent) * self.extent
                size = f"{lv_bytes // MIB}M" if lv_bytes % MIB == 0 else str(lv_bytes)
            else:
                with (self.directory / "system.qcow2").open("rb") as image:
                    size = f"{struct.unpack_from('>Q', image.read(32), 24)[0] // GIB}G"
            if self.simulate == "wrong-size":
                size = "32M"
            self.cfg[slot] = ",".join([f"local-lvm:vm-100-disk-{len(self.sets)+1}", *opts, f"size={size}"])
            self.cfg["digest"] = hashlib.sha1(str(len(self.sets)).encode()).hexdigest()
            if self.simulate == "changed-boot":
                self.cfg["boot"] = "order=net0"
            if self.simulate == "started-during-import":
                self.status = "running"
            if self.simulate == "changed-raw" and len(self.sets) == 1:
                with (self.directory / "restore.raw").open("r+b") as image:
                    image.write(b"replaced")
            if self.simulate == "changed-current-upload" and len(self.sets) == 1:
                with (self.directory / "system.qcow2").open("r+b") as image:
                    image.write(b"replaced")
            if self.simulate == "interrupted-after-set" and len(self.sets) == 1:
                raise Stop("lost response")
            if self.simulate == "interrupted-after-carrier-set" and len(self.sets) == 2:
                raise Stop("lost carrier response")
            if self.simulate == "changed-pool" and len(self.sets) == 1:
                self.storage_config["thinpool"] = "other-pool"
            return "ok"
        raise AssertionError(cmd)


class Staging(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.state = self.directory / "state"
        self.state.mkdir()
        self.pve = StubPVE(self.directory)
        self.patch = patch.dict(stage, command=self.pve, read_mbr=fixture_read_mbr,
                                stage_lock=lambda *_: contextlib.nullcontext())
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.write_sources(15, 512, b"IMWRT-RESTORE-V2\n")
        self.check_sources()

    def write_sources(self, disk_gib, boot_mib, marker, raw_mib=4):
        head = bytearray(4096)
        head[:4] = b"QFI\xfb"
        struct.pack_into(">I", head, 4, 3)
        struct.pack_into(">Q", head, 24, disk_gib * GIB)
        head[2048:2560] = fixture_mbr(disk_gib, boot_mib)
        raw = bytearray(raw_mib * MIB)
        member = tarfile.TarInfo("RESTORE.ID")
        member.size = len(marker)
        raw[:512] = member.tobuf(tarfile.USTAR_FORMAT)
        raw[512:512 + len(marker)] = marker
        (self.directory / "system.qcow2").write_bytes(head)
        (self.directory / "restore.raw").write_bytes(raw)
        self.args = ["100", "local:import/system.qcow2", "local:import/restore.raw",
                     "local-lvm", hashlib.sha256(head).hexdigest(), hashlib.sha256(raw).hexdigest()]
    def check_sources(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.sources, self.hashes, self.sizes = stage["inputs"](*self.args)
        return output.getvalue()

    def invoke(self, mode):
        with contextlib.redirect_stdout(io.StringIO()) as output, patch.dict(stage, save=self.save):
            stage["run"](mode, "100", self.sources, self.hashes, self.sizes, "local-lvm",
                         state_dir=self.state, node="test")
        return output.getvalue()

    @staticmethod
    def save(file, data):
        # JSON is round tripped in all tests; Linux fsync/flock are host primitives.
        file.write_text(json.dumps(data), encoding="utf-8")

    def test_read_only_plan_and_stopped_guard(self):
        self.pve.status = "running"
        self.invoke("plan")
        self.assertEqual(list(self.state.iterdir()), [])
        with self.assertRaisesRegex(Stop, "Shut down"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, [])

    def test_previous_carrier_is_refused_even_with_matching_upload_hash(self):
        path = self.directory / "restore.raw"
        old = path.read_bytes().replace(b"IMWRT-RESTORE-V2", b"IMWRT-RESTORE-V1", 1)
        path.write_bytes(old)
        self.args[-1] = hashlib.sha256(old).hexdigest()
        with self.assertRaises(Stop):
            stage["inputs"](*self.args)
        self.assertEqual(self.pve.sets, [])

    def test_custom_layout_replays_its_own_disks(self):
        self.invoke("stage")
        before = {k: self.pve.cfg[k] for k in ("scsi2", "scsi3")}
        self.write_sources(15, 128, b"IMWRT-RESTORE-V3 15 128\n")
        self.assertIn("disk 15 GiB, boot 128 MiB, root 15231 MiB", self.check_sources())
        for action in ("plan", "stage", "stage"):
            self.invoke(action)
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3", "scsi4", "scsi5"])
        self.assertEqual(before, {k: self.pve.cfg[k] for k in before})

    def test_custom_system_size_and_storage_check(self):
        self.write_sources(24, 256, b"IMWRT-RESTORE-V3 24 256\n")
        self.check_sources()
        self.assertEqual(self.sizes["system"], 24 * GIB)
        self.pve.available = 24 * GIB
        with self.assertRaisesRegex(Stop, "Insufficient"):
            self.invoke("stage")
        self.assertFalse(self.pve.sets)
        self.pve.available += 4 * MIB
        self.invoke("stage")
        self.assertIn("size=24G", self.pve.cfg["scsi2"])

    def test_carrier_extent_rounding_space_and_legacy_interrupted_journal(self):
        self.write_sources(15, 512, b"IMWRT-RESTORE-V2\n", raw_mib=5)
        self.check_sources()
        self.pve.available = 15 * GIB + 8 * MIB - 1
        with self.assertRaisesRegex(Stop, "Insufficient"):
            self.invoke("stage")
        self.assertFalse(self.pve.sets)
        self.pve.available += 1
        self.assertIn("source 5 MiB | target 8388608 bytes", self.invoke("plan"))
        self.assertFalse(list(self.state.iterdir()))
        self.pve.simulate = "interrupted-after-carrier-set"
        with self.assertRaisesRegex(Stop, "lost carrier response"):
            self.invoke("stage")
        self.assertIn("size=8M", self.pve.cfg["scsi3"])
        journal, = self.state.glob("*.json")
        previous = json.loads(journal.read_text())
        del previous["backend"]  # journal written before extent-aware reconciliation
        self.save(journal, previous)
        self.pve.available = 0  # both disks are already attached
        self.invoke("stage")
        self.assertEqual(json.loads(journal.read_text())["rows"]["carrier"]["phase"], "done")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])
        for incorrect in ("5M", "7M", "9M", "12M"):
            with self.subTest(size=incorrect), self.assertRaisesRegex(Stop, "size recorded"), \
                    patch.dict(self.pve.cfg, scsi3=self.pve.cfg["scsi3"].replace("8M", incorrect)):
                self.invoke("stage")

    def test_unknown_extent_unsafe_vg_or_unaligned_system_stops_before_any_disk(self):
        self.pve.extent = 2 * GIB
        with self.assertRaisesRegex(Stop, "would enlarge"):
            self.invoke("stage")
        self.pve.extent = 4 * MIB
        for value in ("0", "4M", "0.5", "<4194304", "511"):
            self.pve.vg_report = {"report": [{"vg": [{"vg_name": "pve-qa", "vg_extent_size": value}]}]}
            with self.subTest(extent=value), self.assertRaisesRegex(Stop, "extent"):
                self.invoke("stage")
        row = {"vg_name": "pve-qa", "vg_extent_size": "4194304"}
        for rows in ([], [dict(row, vg_name="other")], [row, row]):
            self.pve.vg_report = {"report": [{"vg": rows}]}
            with self.subTest(rows=rows), self.assertRaisesRegex(Stop, "extent"):
                self.invoke("stage")
        self.pve.vg_report = None
        for value in ("", "--config", "../pve"):
            with self.subTest(vg=value), patch.dict(self.pve.storage_config, vgname=value), \
                    self.assertRaisesRegex(Stop, "VG and pool"):
                self.invoke("stage")
        self.assertFalse(self.pve.sets)
        self.assertFalse(list(self.state.iterdir()))

    def test_backend_changed_during_staging_stops_and_journal_refuses_replay(self):
        self.pve.simulate = "changed-pool"
        with self.assertRaisesRegex(Stop, "during staging"):
            self.invoke("stage")
        with self.assertRaisesRegex(Stop, "earlier import"):
            self.invoke("stage")
        self.pve.storage_config["thinpool"] = "data"
        with self.assertRaisesRegex(Stop, "automatic reuse is blocked"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])

    def test_mismatched_pair_or_malformed_marker_refused_before_allocation(self):
        for marker in (b"IMWRT-RESTORE-V2\n", b"IMWRT-RESTORE-V3 16 128\n",
                       b"IMWRT-RESTORE-V3 15 256\n", b"IMWRT-RESTORE-V3 15 128\nextra",
                       b"IMWRT-RESTORE-V3 15 0128\n", b"IMWRT-RESTORE-V3 15 4097\n",
                       b"IMWRT-RESTORE-V3 129 128\n", b"IMWRT-RESTORE-V3 2 1536\n"):
            self.write_sources(15, 128, marker)
            with self.subTest(marker=marker), self.assertRaises(Stop):
                self.check_sources()
        self.assertFalse(self.pve.sets)

    def test_shifted_partition_on_expected_size_disk_is_refused(self):
        fw = self.directory / "system.qcow2"
        data = bytearray(fw.read_bytes())
        struct.pack_into("<I", data, 2048 + 462 + 8, 1049601)
        fw.write_bytes(data)
        self.args[4] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(Stop, "partition start"):
            self.check_sources()

    def test_no_changes_to_existing_disks_and_replay(self):
        before = {k: self.pve.cfg[k] for k in ("scsi0", "scsi1", "boot")}
        self.invoke("stage")
        self.assertIn("ro=0,backup=1", self.pve.cfg["scsi2"])
        self.assertIn("ro=1,backup=0", self.pve.cfg["scsi3"])
        self.assertEqual(before, {k: self.pve.cfg[k] for k in before})
        self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])

    def test_reconcile_import_after_lost_response(self):
        self.pve.simulate = "interrupted-after-set"
        with self.assertRaises(Stop):
            self.invoke("stage")
        self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])

    def test_ambiguous_failure_never_reimports(self):
        self.pve.simulate = "ambiguous-empty"
        with self.assertRaises(Stop):
            self.invoke("stage")
        with self.assertRaisesRegex(Stop, "slot is empty"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])

    def test_detached_or_replaced_drive_is_not_overwritten(self):
        self.invoke("stage")
        self.pve.cfg["scsi3"] = "local-lvm:vm-100-disk-45"
        with self.assertRaisesRegex(Stop, "occupied or changed"):
            self.invoke("stage")
        self.assertEqual(len(self.pve.sets), 2)

    def test_no_pending_space_or_efi(self):
        self.pve.pending = [{"key": "scsi5", "pending": "some value"}]
        with self.assertRaisesRegex(Stop, "pending"):
            self.invoke("stage")
        self.pve.pending = []
        self.pve.available = GIB
        with self.assertRaisesRegex(Stop, "Insufficient"):
            self.invoke("stage")
        self.pve.cfg["bios"] = "ovmf"
        with self.assertRaisesRegex(Stop, "SeaBIOS"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, [])

    def test_hash_paths_and_container_headers(self):
        for i, value in [(0, "100;whoami"), (1, "local:import/../system.qcow2"),
                         (2, "local:import/restore.raw,ro=0"), (3, "local,ro=1"), (4, "0" * 64)]:
            bad = self.args.copy()
            bad[i] = value
            with self.subTest(index=i), self.assertRaises(Stop):
                stage["inputs"](*bad)
        fw = self.directory / "system.qcow2"
        data = bytearray(fw.read_bytes())
        data[8] = 1
        fw.write_bytes(data)
        self.args[4] = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(Stop, "standalone"):
            stage["inputs"](*self.args)

    def test_unexpected_carrier(self):
        raw = self.directory / "restore.raw"
        with raw.open("r+b") as handle:
            handle.write(b"WRONG")
        self.args[5] = hashlib.sha256(raw.read_bytes()).hexdigest()
        with self.assertRaisesRegex(Stop, "recovery carrier"):
            stage["inputs"](*self.args)

    def test_ha_vm_stops_prior_to_allocation(self):
        self.pve.ha_managed = 1
        with self.assertRaisesRegex(Stop, "HA-managed"):
            self.invoke("stage")
        self.assertFalse(self.pve.sets)

    def test_boot_changed_outside_staged_slots_stops_second_disk(self):
        self.pve.simulate = "changed-boot"
        with self.assertRaisesRegex(Stop, "hardware changed"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])
        with self.assertRaisesRegex(Stop, "outside the two staging"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])

    def test_late_change_of_already_verified_raw_is_rejected(self):
        self.pve.simulate = "changed-raw"
        with self.assertRaisesRegex(Stop, "upload changed"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])

    def test_restoring_a_replaced_source_does_not_reuse_the_suspect_volume(self):
        source = self.directory / "system.qcow2"
        original = source.read_bytes()
        self.pve.simulate = "changed-current-upload"
        with self.assertRaisesRegex(Stop, "upload changed"):
            self.invoke("stage")
        source.write_bytes(original)
        with self.assertRaisesRegex(Stop, "automatic reuse is blocked"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])

    def test_regenerating_a_raw_cannot_blindly_restart_partial_staging(self):
        self.pve.simulate = "ambiguous-empty"
        with self.assertRaises(Stop):
            self.invoke("stage")
        self.hashes["carrier"] = "f" * 64
        with self.assertRaisesRegex(Stop, "different import"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])

    def test_wrong_target_size_halts_and_keeps_original_disks(self):
        self.pve.simulate = "wrong-size"
        with self.assertRaisesRegex(Stop, "size recorded by PVE"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])
        self.assertEqual(self.pve.cfg["boot"], "order=scsi0")

    def test_vm_started_mid_import_is_reported(self):
        self.pve.simulate = "started-during-import"
        with self.assertRaisesRegex(Stop, "VM state or hardware changed"):
            self.invoke("stage")
        self.assertEqual(self.pve.sets, ["scsi2"])

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires a Linux root-owned test directory")
    def test_durable_state_and_exclusive_real_linux_lock(self):
        directory = self.directory / "durable"
        with native_lock(directory, "100"):
            with self.assertRaises(BlockingIOError), native_lock(directory, "100"):
                self.fail("a second operation obtained the same VM lock")
        with patch.dict(stage, stage_lock=native_lock), contextlib.redirect_stdout(io.StringIO()):
            for _ in range(2):
                stage["run"]("stage", "100", self.sources, self.hashes, self.sizes, "local-lvm",
                             state_dir=directory, node="test")
        journals = list(directory.glob("*.json"))
        self.assertEqual(len(journals), 1)
        self.assertEqual(journals[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(journals[0].read_text())["rows"]["carrier"]["phase"], "done")
        self.assertEqual(self.pve.sets, ["scsi2", "scsi3"])

    @linux_qemu
    def test_cli_plan_stage_replay_with_real_qcow2_conversion(self):
        self.check_cli_roundtrip(15, 512, b"IMWRT-RESTORE-V2\n")

    @linux_qemu
    def test_cli_custom_disk_with_real_qcow2_conversion(self):
        self.check_cli_roundtrip(3, 128, b"IMWRT-RESTORE-V3 3 128\n", raw_mib=5)

    def check_cli_roundtrip(self, disk_gib, boot_mib, marker, raw_mib=4):
        self.write_sources(disk_gib, boot_mib, marker, raw_mib=raw_mib)
        original = self.directory / "synthetic.raw"
        system = self.directory / "system.qcow2"
        with original.open("wb") as raw:
            raw.truncate(disk_gib * GIB)
            raw.write(fixture_mbr(disk_gib, boot_mib))
            for offset in (boot_mib * MIB, disk_gib * GIB - 512):
                raw.seek(offset)
                raw.write(b"synthetic-data-for-integration")
        subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", original, system], check=True)
        self.args[4] = hashlib.sha256(system.read_bytes()).hexdigest()
        allocated = []
        rounded_raw_bytes = ((raw_mib * MIB + self.pve.extent - 1) // self.pve.extent) * self.pve.extent

        def node_command(*args):
            if args[:2] == ("qm", "set"):
                is_system = "ro=0" in args[-1]
                source = system if is_system else self.directory / "restore.raw"
                dest = self.directory / f"import-{len(allocated)}.raw"
                fmt = "qcow2" if is_system else "raw"
                with dest.open("xb") as volume:
                    volume.truncate(disk_gib * GIB if is_system else rounded_raw_bytes)
                subprocess.run(["qemu-img", "convert", "-n", "-f", fmt, "-O", "raw", source, dest], check=True)
                subprocess.run(["qemu-img", "compare", "-q", "-f", fmt, "-F", "raw", source, dest], check=True)
                allocated.append(dest)
            return self.pve(*args)

        impl = stage["run"]
        def isolated_run(*args):
            impl(*args, state_dir=self.directory / "pve-state", node="synthetic")

        with patch.dict(stage, command=node_command, run=isolated_run, stage_lock=native_lock,
                        read_mbr=native_read_mbr), contextlib.redirect_stdout(io.StringIO()):
            for action in ("plan", "stage", "stage"):
                with patch.object(sys, "argv", ["pve-stage.sh", action, *self.args]):
                    stage["main"]()
        self.assertEqual(len(allocated), 2)
        self.assertEqual(allocated[0].stat().st_size, disk_gib * GIB)
        self.assertEqual(allocated[1].stat().st_size, rounded_raw_bytes)
        self.assertEqual(self.pve.cfg["boot"], "order=scsi0")


if __name__ == "__main__":
    unittest.main()
