"""Run ImageBuilder and the independent, network-isolated guest boot test."""
import csv
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

from .artifacts import ROOT, check, load_verified_firmware, release_number, remember_boot_test
from .layout import DEFAULT_LAYOUT
from .localpaths import checked_path
from .releases import prepare_inputs, verify_staged_inputs


def run(args, log, *, quiet=False):
    cmd = [str(a) for a in args]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError as exc:
        raise RuntimeError("找不到 Docker CLI。请安装并启动 Docker Desktop（Linux 引擎），或在向导中载入成品 ZIP。") from exc
    tail = []
    try:
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            tail.append(line)
            if len(tail) > 12:
                tail.pop(0)
            if not quiet:
                log(line)
        status = proc.wait()
    except BaseException:
        proc.terminate()
        proc.wait()
        raise
    finally:
        proc.stdout.close()
    if status:
        raise RuntimeError("Docker 操作失败（退出码 %s）。\n%s" % (status, "\n".join(tail[-6:])))
    return "\n".join(tail)


def mount(source, target, readonly=True):
    fields = ["type=bind", "source=" + str(Path(source).resolve()), "target=" + target]
    if readonly:
        fields.append("readonly")
    text = io.StringIO()
    csv.writer(text, lineterminator="\n").writerow(fields)
    return text.getvalue().rstrip("\n")


def local_docker(log):
    # context show/inspect read local CLI metadata. No daemon connection until the socket is checked.
    endpoint = os.environ.get("DOCKER_HOST")
    if not endpoint or os.environ.get("DOCKER_CONTEXT"):
        context = run(["docker", "context", "show"], log, quiet=True)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", context):
            raise RuntimeError("无法识别本地 Docker context。")
        endpoint = run(["docker", "context", "inspect", context, "--format",
                        '{{(index .Endpoints "docker").Host}}'], log, quiet=True)
    local_pipe = re.fullmatch(r"npipe:////\./pipe/[A-Za-z0-9_.-]+", endpoint, flags=re.I)
    if not (local_pipe or endpoint.startswith("unix:///") and not endpoint.startswith("unix:////")):
        raise RuntimeError("当前 Docker 指向远程端点。请切换到本机 Linux 引擎后重试。")
    return ["docker", "--host", endpoint]


def tool_image(recipe, role, temp, log, docker):
    context = temp / ("context-" + role)
    context.mkdir()
    shutil.copyfile(recipe, context / "Dockerfile")
    key = hashlib.sha256(recipe.read_bytes()).hexdigest()[:16]
    tag = f"routerupgrade-{role}:{key}"
    # Only one explicit Dockerfile is sent to the Docker daemon.
    run([*docker, "build", "--builder", "default", "--platform", "linux/amd64", "--progress=plain", "-t", tag, context], log)
    return tag


@contextmanager
def exclusive_build(path):
    """Kernel locks automatically release on crash; the empty lock file may remain."""
    f = path.open("a+b")
    try:
        if not f.tell():
            f.write(b"0")
            f.flush()
        f.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise RuntimeError("同一版本正在另一个进程中构建。请等待它结束。") from exc
        yield
    finally:
        f.close()


def copy_build_code(stage):
    """Explicit allowlist excludes any adjacent settings, private jobs, or logs."""
    stage.mkdir()
    for name in ("ib-build.sh", "ib-configure.py", "ib-overlay.py", "ib-hotplug.py",
                 "ib-verify-packages.py", "precache-apk.py", "check-ext4.sh",
                 "finalize.sh", "package_bios.py", "verify_bios_image.py", "layout.py"):
        shutil.copyfile(ROOT / name, stage / name)
    templates = stage / "templates"
    templates.mkdir()
    for name in ("AdGuardHome", "adguardhome-native", "router-packages.txt"):
        shutil.copyfile(ROOT / "templates" / name, templates / name)


def layout_args(layout):
    return ["--disk-gib", str(layout.disk_gib), "--boot-mib", str(layout.boot_mib)]


def certify(stage, version, boot_image, log, docker, layout=DEFAULT_LAYOUT):
    disk = stage / "router.qcow2"
    result = run([*docker, "run", "--rm", "--pull=never", "--platform", "linux/amd64",
                  "--network", "none", "--mount", mount(disk, "/disk.qcow2"),
                  "--mount", mount(stage / "router.manifest", "/router.manifest"),
                  "--mount", mount(ROOT / "boot-test.sh", "/boot-test.sh"),
                  "--mount", mount(ROOT / "layout.py", "/layout.py"),
                  boot_image, "bash", "/boot-test.sh", "/disk.qcow2", version, "/router.manifest",
                  *layout_args(layout)], log)
    if "PASS:" not in result:
        raise RuntimeError("启动测试没有返回客体运行证明。")
    report = stage / "verification.json"
    data = json.loads(report.read_text("utf-8"))
    data.update(boot_verified=True, boot_test="SeaBIOS / VirtIO SCSI / no NIC / temporary snapshot",
                tested_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), output="router.qcow2")
    report.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return check(stage, version, layout=layout)


def build_firmware(version, public_dir, log=print, layout=DEFAULT_LAYOUT):
    version = release_number(version)
    root = checked_path(public_dir, allow_missing=True)
    root.mkdir(parents=True, exist_ok=True)
    target = root / layout.cache_name(version)
    cached = load_verified_firmware(version, root, log=log, layout=layout)
    if cached:
        return cached
    # Layouts for the same version share authenticated downloads. Serialize
    # builds so the Windows cache cannot be replaced while another job copies it.
    with exclusive_build(root / (".building-" + version)):
        cached = load_verified_firmware(version, root, log=log, layout=layout)
        if cached:
            return cached
        docker = local_docker(log)
        if run([*docker, "info", "--format", "{{.OSType}}"], log, quiet=True).strip() != "linux":
            raise RuntimeError("请在 Docker Desktop 切换到 Linux containers。")
        inputs = prepare_inputs(version, root / "downloads" / version, log)
        record = root / ("build-" + target.name.removeprefix("firmware-") + "-" + uuid.uuid4().hex[:8] + ".log")
        log(f"公开构建日志：{record}")
        with tempfile.TemporaryDirectory(prefix=".work-", dir=root) as job, record.open("x", encoding="utf-8") as f:
            temp = Path(job)
            def output(message):
                f.write(str(message) + "\n")
                f.flush()
                log(message)
            tool = tool_image(ROOT / "Dockerfile.imagebuilder", "builder", temp, output, docker)
            boot = tool_image(ROOT / "boot" / "Dockerfile", "seabios", temp, output, docker)
            stage, engine, selected = temp / "out", temp / "engine", temp / "inputs"
            stage.mkdir()
            selected.mkdir()
            copy_build_code(engine)
            for name in ("imagebuilder.tar.zst", "AdGuardHome.tar.gz", "sha256sums", "sha256sums.sig"):
                shutil.copyfile(checked_path(Path(inputs) / name), selected / name)
            verify_staged_inputs(version, selected)
            (selected / "version.txt").write_bytes((version + "\n").encode("ascii"))
            name = "routerupgrade-" + uuid.uuid4().hex
            try:
                run([*docker, "run", "--rm", "--name", name, "--pull=never", "--platform", "linux/amd64",
                     "--mount", mount(selected, "/inputs"), "--mount", mount(engine, "/engine"),
                     "--mount", mount(stage, "/out", False), tool,
                     "bash", "-ec", 'bash /engine/ib-build.sh "$@" && bash /engine/finalize.sh "$@"',
                     "routerupgrade", *layout_args(layout)], output)
            except BaseException:
                # May have a running container when the local docker client was interrupted.
                subprocess.run([*docker, "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                raise
            manifests = list(stage.glob("*.manifest"))
            if len(manifests) != 1:
                raise RuntimeError("ImageBuilder 未返回唯一的软件包清单。")
            if manifests[0].name != "router.manifest":
                manifests[0].rename(stage / "router.manifest")
            remember_boot_test(certify(stage, version, boot, output, docker, layout))
            # Export the four verified files before removing the full transient IB outputs.
            delivery = temp / "delivery"
            delivery.mkdir()
            for item in ("router.qcow2", "router.sha256", "router.manifest", "verification.json"):
                (stage / item).rename(delivery / item)
            delivery.rename(target)
        return check(target, version, layout=layout)
