"""Stage only public service assets with correct Linux metadata."""
from pathlib import Path
import shutil
import sys
import tarfile


root = Path(sys.argv[1])
root.mkdir()
templates = Path(__file__).resolve().parent / "templates"
data = root / "usr/bin/AdGuardHome"
data.mkdir(parents=True)
expected = {"AdGuardHome", "AdGuardHome.sig", "LICENSE.txt", "README.md", "CHANGELOG.md"}
seen = set()
with tarfile.open("/inputs/AdGuardHome.tar.gz", "r:gz") as archive:
    for member in archive:
        path = member.name.removeprefix("./")
        if not path.startswith("AdGuardHome/"):
            continue
        name = path.removeprefix("AdGuardHome/")
        if name not in expected:
            continue
        if not member.isfile() or name in seen or not 0 < member.size <= 192 * 1024 * 1024:
            raise SystemExit("Invalid native AdGuard Home release archive")
        seen.add(name)
        dest = data / name
        with archive.extractfile(member) as src, dest.open("xb") as out:
            shutil.copyfileobj(src, out)
        dest.chmod(0o755 if name == "AdGuardHome" else 0o644)
if expected - seen:
    raise SystemExit("Incomplete native AdGuard Home release archive")
with (data / "AdGuardHome").open("rb") as f:
    header = f.read(64)
if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
    raise SystemExit("AdGuard Home is not a Linux x86-64 executable")
for dest, source, mode in [
    ("etc/init.d/AdGuardHome", "AdGuardHome", 0o755),
    ("lib/upgrade/keep.d/adguardhome-native", "adguardhome-native", 0o644),
]:
    output = root / dest
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(templates / source, output)
    output.chmod(mode)
rc = root / "etc/rc.d"
rc.mkdir()
for entry in ("S95AdGuardHome", "K01AdGuardHome"):
    (rc / entry).symlink_to("../init.d/AdGuardHome")
