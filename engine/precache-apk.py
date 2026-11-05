"""Mirror just the packages selected by the signed x86/64 ImageBuilder."""
import concurrent.futures
from http.client import IncompleteRead
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


INDEX_LIMIT = 64 * 1024**2
APK_LIMIT = 256 * 1024**2


def official_authority(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "downloads.immortalwrt.org":
        raise ValueError("Expected the official HTTPS ImmortalWrt package host")


class OfficialRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        official_authority(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, path):
    # A partial download must never be mistaken for a complete package.
    temp = path.with_suffix(path.suffix + ".part")
    official_authority(url)
    limit = INDEX_LIMIT if path.name == "packages.adb" else APK_LIMIT
    opener = urllib.request.build_opener(OfficialRedirect)
    for attempt in range(3):
        try:
            with opener.open(url, timeout=35) as source, temp.open("wb") as target:
                official_authority(source.geturl())
                length = source.headers.get("Content-Length")
                if length is not None and (not length.isdecimal() or not 0 < int(length) <= limit):
                    raise ValueError("Official package download has an invalid length")
                while chunk := source.read(256 * 1024):
                    if target.tell() + len(chunk) > limit:
                        raise ValueError("Official package download exceeds its size limit")
                    target.write(chunk)
                if target.tell() == 0 or (length is not None and target.tell() != int(length)):
                    raise IOError("Truncated package download")
            os.replace(temp, path)
            return
        except (OSError, IncompleteRead):
            if attempt == 2:
                raise
            time.sleep(attempt + 1)
        finally:
            temp.unlink(missing_ok=True)


def signed_index_urls(config):
    urls = [s.strip() for s in config.splitlines() if s.strip() and not s.lstrip().startswith("#")]
    for url in urls:
        p = urllib.parse.urlsplit(url)
        if (p.scheme != "https" or p.netloc != "downloads.immortalwrt.org" or p.query or p.fragment
                or not re.fullmatch(r"/releases/[0-9]+\.[0-9]+\.[0-9]+/[A-Za-z0-9_./~-]+/packages\.adb", p.path)
                or ".." in p.path.split("/")):
            raise ValueError("Unrecognized official release repository: " + url)
    if not urls or len(urls) != len(set(urls)):
        raise ValueError("Missing or duplicate APK repositories")
    return urls


def package_constraints(job, world_path, scratch):
    requests = world_path.read_text().split()
    if not requests or any(not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(=[0-9A-Za-z][0-9A-Za-z_.+~-]*)?", s) for s in requests):
        raise ValueError("Invalid package request for APK")
    # Use ImageBuilder's own resolved default, profile, requested and pinned
    # kernel/libc/base-files sets, exactly as its package_install target does.
    recipe = scratch / "world.mk"
    recipe.write_text("include Makefile\n.PHONY: wizard_world\nwizard_world:\n\t@printf '%s\\n' $(BUILD_PACKAGES)\n")
    result = subprocess.check_output(["make", "-s", "-f", str(recipe), "USER_PROFILE=DEVICE_generic",
                                      "USER_PACKAGES=" + " ".join(requests), "wizard_world"], cwd=job, text=True)
    constraints = result.split()
    if not set(requests) <= set(constraints) or not any(s.startswith("kernel=") for s in constraints):
        raise RuntimeError("ImageBuilder did not return the expected generic package set")
    return constraints


def precache(world_path):
    job = Path.cwd()
    repositories = job / "repositories"
    original = repositories.read_text()
    remote = signed_index_urls(original)
    apk = str(job / "staging_dir/host/bin/apk")
    keyargs = ["--keys-dir", str(job / "keys")]
    mirror = job / "official-feeds"
    mirror.mkdir()
    # Don't change ImageBuilder repositories until the complete public mirror
    # has been authenticated, including every package selected by its solver.
    local_indexes = []
    sources = {}
    for i, url in enumerate(remote):
        directory = mirror / str(i)
        directory.mkdir()
        local_indexes.append(directory / "packages.adb")
        sources[directory] = url.rsplit("/", 1)[0] + "/"
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(download, remote, local_indexes))
    subprocess.run([apk, "verify", *keyargs, *map(str, local_indexes)], check=True)
    subprocess.run(["make", "-s", "_check_keys"], check=True)
    subprocess.run(["make", "-s", "package_index"], check=True)
    bundled_index = job / "packages/packages.adb"
    subprocess.run([apk, "verify", *keyargs, str(bundled_index)], check=True)
    local_config = mirror / "repositories.local"
    local_config.write_text("".join(str(i) + "\n" for i in local_indexes))
    with tempfile.TemporaryDirectory(dir=job, prefix="apk-check-") as tmp:
        scratch = Path(tmp)
        fetch = [apk, "fetch", "--arch", "x86_64", *keyargs, "--repositories-file", str(local_config),
                 "--repository", str(bundled_index), "--recursive"]
        world = package_constraints(job, world_path, scratch)
        result = subprocess.check_output([*fetch, "--url", "--simulate", *world], text=True)
        packages = []
        for line in result.splitlines():
            path = Path(line)
            if not path.is_absolute() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_+.%~-]*\.apk", path.name):
                raise RuntimeError("Unexpected result from the native package solver: " + line)
            if path.parent == bundled_index.parent:
                if not path.is_file():
                    raise FileNotFoundError(path)
                continue
            if path.parent not in sources:
                raise RuntimeError("Package outside verified repositories: " + line)
            packages.append(path)
        if not packages or len(packages) != len(set(packages)):
            raise RuntimeError("Expected a nonempty, unique APK solution")
        print(f"Downloading {len(packages)} official packages (8 concurrent connections)...", flush=True)
        urls = [sources[p.parent] + urllib.parse.quote(p.name, safe="+~") for p in packages]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for n, _ in enumerate(pool.map(download, urls, packages), 1):
                if n % 40 == 0:
                    print(f"Public packages: {n}/{len(packages)}", flush=True)
        # Official .apk files need not be independently signed. fetch checks
        # their identities against the authenticated indexes, and their payloads.
        subprocess.run([*fetch, "--no-network", "-o", str(scratch), *world], check=True)
    (job / "repositories.online").write_text(original)
    os.replace(local_config, repositories)
    print(f"Verified {len(local_indexes)} signed APK indexes and the complete package selection.", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: precache-apk.py REQUESTED_PACKAGE_LIST (run inside extracted ImageBuilder)")
    precache(Path(sys.argv[1]).resolve(strict=True))
