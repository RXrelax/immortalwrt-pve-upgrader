"""Keep the system mounts while retaining automount for other disks."""
from pathlib import Path
import sys

hook = Path(sys.argv[1]) / "etc/hotplug.d/block/15-automount"
original = hook.read_text()
start = "\t\tadd)\n"
if original.count(start) != 1:
    sys.exit("Unknown 15-automount add handler; inspect the new release before installing.")
guard = """\t\t\t# A replayed add event must not mount the system disk a second time.
\t\t\tif [ -r "/sys/class/block/$device/dev" ] &&
\t\t\t   awk -v dev="$(cat "/sys/class/block/$device/dev")" '
\t\t\t       $3 == dev && ($5 == "/" || $5 == "/boot") { mounted=1 }
\t\t\t       END { exit !mounted }
\t\t\t   ' /proc/self/mountinfo; then
\t\t\t\treturn 0
\t\t\tfi
"""
hook.write_text(original.replace(start, start + guard))
