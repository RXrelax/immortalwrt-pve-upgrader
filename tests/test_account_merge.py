"""Exercise the shipped guest account transaction under an isolated synthetic root."""
import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

from engine.private_carrier import _RUN_SCRIPT


ROOT_PASSWD = b"root:x:0:0:root:/root:/bin/ash\n"
DAEMON = b"daemon:*:1:1:daemon:/var:/bin/false\n"
HELPER = b"helper:*:104:1:helper:/var:/bin/false\n"
NEW = b"newapp:*:200:200:newapp:/var:/bin/false\n"
SOURCE_SHADOW = b"root:$synthetic-hash:1:0:99999:7:::\n"
ORIGINAL = {
    "passwd": ROOT_PASSWD + DAEMON + HELPER,
    "group": b"root:x:0:\nservice:x:1:daemon,helper\n",
    "shadow": b"root:!:1:0:99999:7:::\nhelper:!:1:0:99999:7:::\n",
    "gshadow": b"service:!:helper:daemon,helper\n",
}
SOURCE = {
    "passwd": ROOT_PASSWD + DAEMON + NEW,
    "group": b"root:x:0:\nservice:x:1:newapp\nnewapp:x:200:\n",
    "shadow": SOURCE_SHADOW,
    "gshadow": b"service:!:newapp:newapp\n",
}


@unittest.skipUnless(os.name == "posix" and shutil.which("sh") and shutil.which("tar") and shutil.which("awk"),
                     "uses the guest's POSIX shell, tar, awk and file permissions")
class GuestAccounts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.etc = base / "target/etc"
        self.etc.mkdir(parents=True)
        self.stage = base / "stage"
        self.stage.mkdir()
        for table, data in ORIGINAL.items():
            dest = self.etc / table
            dest.write_bytes(data)
            dest.chmod(0o640 if table in ("shadow", "gshadow") else 0o644)

    def run_restore(self, source, *, prefix="", marker_fixture="migration-probe"):
        paths = dict(source)
        paths[marker_fixture] = b"ordinary data"
        with tarfile.open(self.stage / "RESTORE.TGZ", "w:gz") as tar:
            for name, data in paths.items():
                m = tarfile.TarInfo("etc/" + name)
                m.size = len(data)
                m.mode = 0o777
                tar.addfile(m, io.BytesIO(data))
        (self.stage / "members").write_text("".join("etc/" + key + "\n" for key in paths))
        # Execute real checks and ordinary extraction. Redirect only the
        # absolute target root and account files into the generated directory.
        block = _RUN_SCRIPT.decode().split("# Package users and groups", 1)[1]
        block = "# Package users and groups" + block.split("# Account transaction complete.", 1)[0]
        block = block.replace('"/etc/', '"$test_root/etc/').replace("groups=/etc/group", 'groups="$test_root/etc/group"')
        block = block.replace('-C / -xzpf', '-C "$test_root" -xzpf')
        cmd = ('umask 077; stage=$PWD; test_root=$(cd ../target && pwd); '
               'fail() { echo "$1" >&2; exit 1; }; begin_restore() { :; }\n' + prefix + "\n" + block)
        return subprocess.run(["sh", "-c", cmd], cwd=self.stage, text=True, capture_output=True)

    def test_keeps_target_only_service_members_and_preserves_target_permissions(self):
        done = self.run_restore(SOURCE)
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertIn(HELPER, (self.etc / "passwd").read_bytes())
        self.assertIn(NEW, (self.etc / "passwd").read_bytes())
        self.assertIn(b"service:x:1:newapp,helper\n", (self.etc / "group").read_bytes())
        self.assertIn(b"service:!:newapp,helper:newapp,helper\n", (self.etc / "gshadow").read_bytes())
        shadow = self.etc / "shadow"
        self.assertIn(SOURCE_SHADOW, shadow.read_bytes())
        self.assertEqual(0o640, stat.S_IMODE(shadow.stat().st_mode))

    def test_duplicate_uid_unknown_gid_and_bad_shadow_refused_before_write(self):
        for key, data in (("passwd", ROOT_PASSWD + NEW + NEW.replace(b"newapp", b"dup")),
                          ("passwd", ROOT_PASSWD + NEW.replace(b":200:200:", b":200:777:")),
                          ("passwd", ROOT_PASSWD + NEW.replace(b":200:200:", b":200:-1:")),
                          ("passwd", ROOT_PASSWD + NEW.replace(b":200:200:", b":104:200:")),
                          ("group", SOURCE["group"] + b"duplicate:x:200:\n"),
                          ("shadow", b"root:invalid\n")):
            with self.subTest(key=key, data=data):
                done = self.run_restore(dict(SOURCE, **{key: data}))
                self.assertNotEqual(0, done.returncode)
                self.assertFalse((self.etc / "migration-probe").exists())
                self.assertEqual((self.etc / "shadow").read_bytes(), ORIGINAL["shadow"])

    def test_failing_ordinary_tar_does_not_replace_accounts(self):
        prefix = '''
tar() {
    command tar "$@" || return 1
    for option in "$@"; do [ "$option" != -xzpf ] || return 1; done
    return 0
}
'''
        done = self.run_restore(SOURCE, prefix=prefix)
        self.assertNotEqual(0, done.returncode)
        self.assertTrue((self.etc / "migration-probe").exists())
        for table, data in ORIGINAL.items():
            self.assertEqual((self.etc / table).read_bytes(), data)

    def test_interrupted_account_install_rolls_back_preceding_account_tables(self):
        prefix = '''
mv() {
    case "$3" in */etc/passwd) return 1;; esac
    command mv "$@"
}
'''
        done = self.run_restore(SOURCE, prefix=prefix)
        self.assertNotEqual(0, done.returncode)
        for table, data in ORIGINAL.items():
            self.assertEqual((self.etc / table).read_bytes(), data)
