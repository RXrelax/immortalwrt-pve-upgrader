"""Compare the release manifest with the final rootfs package database."""
import json
from pathlib import Path
import re
import sys


def manifest_versions(text):
    result = {}
    for line in text.splitlines():
        package = re.fullmatch(r"(\S+) - (\S+)", line)
        if not package or package[1] in result:
            raise ValueError("Malformed or duplicate manifest entry")
        result[package[1]] = package[2]
    return result


def verify_packages(manifest, installed, requests):
    versions = {}
    available = set()
    for package in installed:
        name, version = package["name"], package["version"]
        if name in versions or not name or not version:
            raise ValueError("Malformed or duplicate installed package entry")
        versions[name] = version
        available.add(name)
        for tag in package.get("tags", []):
            if tag.startswith("openwrt:abiversion="):
                suffix = tag.partition("=")[2]
                if suffix and name.endswith(suffix):
                    available.add(name.removesuffix(suffix))
        for provider in package.get("provides", []):
            if isinstance(provider, str):
                available.add(re.split(r"[=<>~]", provider, maxsplit=1)[0])
    if manifest != versions:
        diff = sorted(n for n in set(manifest) | set(versions) if manifest.get(n) != versions.get(n))
        raise ValueError("Manifest and final APK database differ: " + ", ".join(diff[:12]))
    missing = sorted(set(requests.values()) - available)
    if missing:
        raise ValueError("Requested packages absent from installed metadata: " + ", ".join(missing))
    if "luci-app-openclash" not in versions or "luci-app-adguardhome" in versions:
        raise ValueError("Missing OpenClash or obsolete AdGuardHome LuCI package installed")
    return versions["luci-app-openclash"]


if __name__ == "__main__":
    version, manager, manifest_path = sys.argv[1:]
    if manager != "apk":
        sys.exit("Only the supported APK release series is enabled")
    installed = json.loads(Path("installed.json").read_text())
    requests = dict(line.split("\t") for line in Path("migration-packages.tsv").read_text().splitlines())
    try:
        oc = verify_packages(manifest_versions(Path(manifest_path).read_text()), installed, requests)
    except (KeyError, TypeError, ValueError) as error:
        sys.exit(str(error))
    Path("requested-packages.json").write_text(json.dumps({
        "release": version, "manager": manager, "openclash": oc,
        "requested_to_installed": requests,
    }, indent=2) + "\n")
