"""Public, authenticated build inputs for the x86/64 BIOS upgrade wizard.

No API accepts a backup file, custom URL, or credentials. Package installation
uses the official signed feeds inside ImageBuilder, including OpenClash.
"""

import base64
from hashlib import sha256
from html.parser import HTMLParser
from http.client import IncompleteRead
import io
import os
from pathlib import Path
import re
import shutil
import ssl
import struct
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
import zlib


ROOT = "https://downloads.immortalwrt.org/releases/"
VERSION_RE = re.compile(r"[1-9][0-9]?\.[0-9]{1,2}\.(?:0|[1-9][0-9]{0,2})")
# From the keyring commit pinned by ImmortalWrt v25.12.2:
# github.com/immortalwrt/keyring/blob/14e1f88b521f6466dfcc06b055646cfa25e8e02f/usign/467a35c14d7fbc5c
RELEASE_KEYS = {(25, 12): "RWRGejXBTX+8XLYq8lHqqiiqkeAmXhfP0JxEleqViajPTJ8d/PVqQsDT"}
ADH_VERSION = "0.107.80"
ADH_SHA256 = "28593bc761d71469abdbc6f39ca42cbed763ec92b63082c729177b037ed51d18"
ADH_SIZE = 12553060
ADH_URL = f"https://github.com/AdguardTeam/AdGuardHome/releases/download/v{ADH_VERSION}/AdGuardHome_linux_amd64.tar.gz"
METADATA_LIMIT = 2 * 1024 * 1024
IB_LIMIT = 512 * 1024 * 1024
OFFICIAL_IMAGE_LIMIT = 256 * 1024 * 1024
BLOCK = 1024 * 1024
HOSTS = {"downloads.immortalwrt.org", "github.com", "release-assets.githubusercontent.com",
         "objects.githubusercontent.com"}


class ReleaseError(RuntimeError):
    """User-readable failure; never contains credentials or a signed asset URL."""


def _version(s):
    if not isinstance(s, str) or not VERSION_RE.fullmatch(s):
        raise ReleaseError("固件版本须为三个数字组成的正式版，不能是快照或预览版。")
    return tuple(map(int, s.split(".")))


class _ReleaseIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.versions = set()

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href") if tag == "a" else None
        if href and href.endswith("/") and VERSION_RE.fullmatch(href[:-1]):
            self.versions.add(href[:-1])


def _check_url(url):
    p = urlsplit(url)
    if (p.scheme != "https" or p.hostname not in HOSTS or p.username is not None
            or p.password is not None or p.port not in (None, 443)):
        raise ReleaseError("官方公开资源指向未授权的地址或非 HTTPS，下载已停止。")


class _Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        if urlsplit(req.full_url).hostname == "downloads.immortalwrt.org" and urlsplit(newurl).hostname != "downloads.immortalwrt.org":
            raise ReleaseError("官方固件目录重定向至其他主机，下载已停止。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url, sink, limit):
    """Retry whole transfers. sink must support seek and truncate."""
    _check_url(url)
    opener = build_opener(_Redirect(), HTTPSHandler(context=ssl.create_default_context()))
    for attempt in range(3):
        try:
            sink.seek(0)
            sink.truncate()
            req = Request(url, headers={"User-Agent": "ImmortalWrt-Local-Upgrade/1.0", "Accept-Encoding": "identity"})
            with opener.open(req, timeout=35) as response:
                _check_url(response.geturl())
                declared = response.headers.get("Content-Length")
                if declared is not None and (not declared.isdecimal() or int(declared) > limit):
                    raise ReleaseError("公开下载的文件长度异常。")
                n, digest = 0, sha256()
                while True:
                    part = response.read(BLOCK)
                    if not part:
                        break
                    n += len(part)
                    if n > limit:
                        raise ReleaseError("公开下载超过大小限制。")
                    sink.write(part)
                    digest.update(part)
                if not n or (declared is not None and n != int(declared)):
                    raise OSError("incomplete transfer")
                return n, digest.hexdigest()
        except HTTPError as e:
            if e.code not in (408, 429, 500, 502, 503, 504) or attempt == 2:
                raise ReleaseError(f"读取公开发布资源失败（HTTP {e.code}）。请检查网络或稍后重试。") from None
        except (OSError, URLError, IncompleteRead) as e:
            if attempt == 2:
                raise ReleaseError(f"下载未完成（{type(e).__name__}）。检查网络、TLS 证书及缓存可用空间后可重试。") from None
        time.sleep(1 << attempt)


def _public_bytes(url, limit=METADATA_LIMIT):
    out = io.BytesIO()
    _fetch(url, out, limit)
    return out.getvalue()


def discover(log=None):
    """Return highest numeric stable release on the official release index."""
    page = _ReleaseIndex()
    page.feed(_public_bytes(ROOT).decode("utf-8"))
    if not page.versions:
        raise ReleaseError("官方目录中没有可识别的正式版本，已停止。")
    latest = max(page.versions, key=_version)
    if log:
        log(f"官方稳定版目录：{latest}")
    return latest


def _verify_signature(checksums, signature_file, encoded_key):
    try:
        key = base64.b64decode(encoded_key, validate=True)
        lines = signature_file.splitlines()
        if len(lines) != 2:
            raise ValueError
        signature = base64.b64decode(lines[1], validate=True)
        if len(key) != 42 or len(signature) != 74 or key[:2] != b"Ed" or key[:10] != signature[:10]:
            raise ValueError
    except (ValueError, IndexError):
        raise ReleaseError("校验单签名格式或发布公钥不匹配，请核对官方是否轮换了密钥。") from None
    raw_key, raw_sig = key[10:], signature[10:]
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        # OpenSSL's Ed25519 verifier uses the same (raw, unprehashed) message
        # as ImmortalWrt's usign. No private key or system keyring is used.
        openssl = shutil.which("openssl")
        if not openssl and os.name == "nt":
            git_openssl = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
            if git_openssl.is_file():
                openssl = str(git_openssl)
        if not openssl:
            raise ReleaseError("验签需要 Python cryptography 或 OpenSSL 3（Git for Windows 自带）。请安装其一后重试。")
        with tempfile.TemporaryDirectory(prefix="imwrt-pub-verify-") as d:
            tmp = Path(d)
            (tmp / "key.der").write_bytes(bytes.fromhex("302a300506032b6570032100") + raw_key)
            (tmp / "sig").write_bytes(raw_sig)
            (tmp / "sums").write_bytes(checksums)
            args = [openssl, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", "key.der",
                    "-rawin", "-in", "sums", "-sigfile", "sig"]
            result = subprocess.run(args, cwd=tmp, capture_output=True, timeout=20)
            if result.returncode:
                raise ReleaseError("OpenSSL 未能验证官方校验单（需支持 Ed25519 的 OpenSSL 3）。")
    else:
        try:
            Ed25519PublicKey.from_public_bytes(raw_key).verify(raw_sig, checksums)
        except (InvalidSignature, ValueError):
            raise ReleaseError("官方校验单签名无效，已停止。") from None


def _signed_digest(checksums, name):
    regex = re.compile(rb"^([0-9a-f]{64}) [ *]" + re.escape(name.encode("ascii")) + rb"$")
    matches = [m[1].decode() for line in checksums.splitlines() if (m := regex.fullmatch(line))]
    if len(matches) != 1:
        raise ReleaseError(f"签名校验单中缺少唯一的 {name} 记录。")
    return matches[0]


def _official_mbr(compressed):
    # Only the first sector is needed. Limit both compressed input (including
    # optional gzip header fields) and decompressed output, even for a signed file.
    try:
        mbr = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(compressed.read(64 * 1024), 512)
    except zlib.error:
        raise ReleaseError("官方镜像的 gzip 头无效，无法读取分区表。") from None
    if len(mbr) != 512 or mbr[510:] != b"\x55\xaa" or not any(mbr[:440]):
        raise ReleaseError("官方镜像缺少完整的 BIOS 主引导记录（MBR）。")
    if any(mbr[478:510]):
        raise ReleaseError("官方镜像包含额外的 MBR 分区，无法按双分区布局解释。")
    partitions = []
    previous_end = 1
    for slot in range(2):
        flag, kind, start, length = struct.unpack_from("<B3xB3xII", mbr, 446 + 16 * slot)
        end = start + length
        if (flag != (0x80 if slot == 0 else 0) or kind != 0x83 or not length
                or start < previous_end or end > 2**32):
            raise ReleaseError(f"官方镜像的第 {slot + 1} 个分区不符合 x86 BIOS 布局。")
        partitions.append({"start": start * 512, "bytes": length * 512})
        previous_end = end
    return partitions


def official_layout(version, log=print):
    """Read the two partitions of the authenticated stock BIOS image for this release."""
    key = RELEASE_KEYS.get(_version(version)[:2])
    if not key:
        raise ReleaseError(f"{version} 的官方分区尚未核验：本向导没有该系列的可信发布公钥。")
    base = f"{ROOT}{version}/targets/x86/64/"
    name = f"immortalwrt-{version}-x86-64-generic-ext4-combined.img.gz"
    if log:
        log(f"正在核验 ImmortalWrt {version} 官方 BIOS 镜像的签名清单和 SHA-256…")
    try:
        checksums = _public_bytes(base + "sha256sums")
        signature = _public_bytes(base + "sha256sums.sig", 8192)
        _verify_signature(checksums, signature, key)
        expected = _signed_digest(checksums, name)
        with tempfile.TemporaryFile(mode="w+b") as compressed:
            _, digest = _fetch(base + name, compressed, OFFICIAL_IMAGE_LIMIT)
            if digest != expected:
                raise ReleaseError("整份官方 BIOS 压缩镜像的 SHA-256 与签名清单不符。")
            compressed.seek(0)
            parts = _official_mbr(compressed)
    except ReleaseError as exc:
        raise ReleaseError(f"{version} 的官方分区尚未核验：{exc}") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseError(f"{version} 的官方分区尚未核验：读取临时文件或运行验签程序失败（{type(exc).__name__}）。") from exc
    return {"version": version, "image_name": name, "sha256": digest, "partitions": parts,
            "boot_mib": parts[0]["bytes"] / 1024**2, "root_mib": parts[1]["bytes"] / 1024**2}


def _file_digest(path):
    h = sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(BLOCK), b""):
            h.update(block)
    return h.hexdigest()


def _store_public_metadata(path, data):
    if path.is_symlink():
        raise ReleaseError("公开校验文件路径是符号链接，已停止。")
    temp = tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".metadata-", delete=False)
    try:
        with temp:
            temp.write(data)
        os.replace(temp.name, path)
    finally:
        Path(temp.name).unlink(missing_ok=True)


def _asset(url, dest, expected, limit, log, exact_size=None):
    if dest.is_symlink() or (dest.exists() and not dest.is_file()):
        raise ReleaseError("公开缓存目标不是普通文件，请选择新的缓存目录。")
    if dest.is_file() and dest.stat().st_size <= limit and (exact_size is None or dest.stat().st_size == exact_size):
        if _file_digest(dest) == expected:
            log(f"缓存校验通过：{dest.name}")
            return
    log(f"下载并验证：{dest.name}")
    temp = tempfile.NamedTemporaryFile(mode="w+b", dir=dest.parent, prefix=".public-", suffix=".part", delete=False)
    temp_path = Path(temp.name)
    try:
        with temp:
            size, digest = _fetch(url, temp, limit)
            if digest != expected or (exact_size is not None and size != exact_size):
                raise ReleaseError("公开文件 SHA-256 或长度不符，未使用该文件。")
        os.replace(temp_path, dest)
    finally:
        temp_path.unlink(missing_ok=True)


def _builder_key(version):
    series = _version(version)[:2]
    if series != (25, 12) or series not in RELEASE_KEYS:
        raise ReleaseError(f"{version} 尚无本向导验证过的 APK 构建方案和发布公钥。请更新向导后再试。")
    return RELEASE_KEYS[series]


def _signed_builder(version, checksums, signature):
    name = f"immortalwrt-imagebuilder-{version}-x86-64.Linux-x86_64.tar.zst"
    _verify_signature(checksums, signature, _builder_key(version))
    return name, _signed_digest(checksums, name)


def verify_staged_inputs(version, folder):
    """Offline, reauthenticate the exact staged copies about to enter the builder."""
    path = Path(folder)
    sums, sig = path / "sha256sums", path / "sha256sums.sig"
    builder, adh = path / "imagebuilder.tar.zst", path / "AdGuardHome.tar.gz"
    for file, limit in ((sums, METADATA_LIMIT), (sig, 8192), (builder, IB_LIMIT), (adh, ADH_SIZE)):
        if file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= limit:
            raise ReleaseError("公开构建输入副本或签名文件缺失、类型或长度异常。")
    _, expected = _signed_builder(version, sums.read_bytes(), sig.read_bytes())
    if (_file_digest(builder) != expected or adh.stat().st_size != ADH_SIZE or
            _file_digest(adh) != ADH_SHA256):
        raise ReleaseError("即将用于构建的副本 SHA-256 与签名清单或上游固定值不匹配，已停止。")


def prepare_inputs(version, path, log=print):
    """Verify and place only public archives directly in path. Return pathlib.Path."""
    _builder_key(version)  # Reject unsupported release families before any network request.
    folder = Path(path)
    folder.mkdir(parents=True, exist_ok=True)
    base = f"{ROOT}{version}/targets/x86/64/"
    checksums = _public_bytes(base + "sha256sums")
    signature = _public_bytes(base + "sha256sums.sig", 8192)
    name, expected = _signed_builder(version, checksums, signature)
    log(f"ImmortalWrt {version} 发布签名通过，ImageBuilder SHA-256 {expected}")
    _asset(base + name, folder / "imagebuilder.tar.zst", expected, IB_LIMIT, log)
    _asset(ADH_URL, folder / "AdGuardHome.tar.gz", ADH_SHA256, ADH_SIZE, log, ADH_SIZE)
    _store_public_metadata(folder / "sha256sums", checksums)
    _store_public_metadata(folder / "sha256sums.sig", signature)
    log(f"AdGuard Home v{ADH_VERSION}：已与核验过的官方 SHA-256 匹配")
    return folder
