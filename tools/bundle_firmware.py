"""Package a verified default-layout release disk and optionally record its pin."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
from engine.artifacts import FILES, digest, load_verified_firmware, release_number  # noqa: E402
from engine.layout import DEFAULT_LAYOUT  # noqa: E402


def package(version, public_dir, output_dir, record=False):
    release_number(version)
    verified = load_verified_firmware(version, public_dir, layout=DEFAULT_LAYOUT)
    if verified is None:
        raise ValueError("请先完成该版本默认布局的本地冷启动验收，或导入已核验的公开发行包。")
    source = verified["qcow2"].parent
    expected = {"router.qcow2": verified["sha256"], "verification.json": verified["report_sha256"],
                "router.manifest": digest(source / "router.manifest"),
                "router.sha256": digest(source / "router.sha256")}
    output = Path(output_dir) / f"RouterUpgrade-firmware-{version}.zip"
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as fp:
            try:
                with ZipFile(fp, "w", ZIP_DEFLATED) as bundle:
                    for name in FILES:
                        info = ZipInfo(name, (2020, 1, 1, 0, 0, 0))
                        info.compress_type = ZIP_DEFLATED
                        with (source / name).open("rb") as f, bundle.open(info, "w") as dest:
                            shutil.copyfileobj(f, dest, 2**20)
            except BaseException:
                fp.close()
                output.unlink()
                raise
    except FileExistsError:
        raise SystemExit("该版本的发布包已存在。请选择新的目标目录。")
    with ZipFile(output) as bundle:
        for name in FILES:
            h = hashlib.sha256()
            with bundle.open(name) as f:
                for b in iter(lambda: f.read(2**20), b""):
                    h.update(b)
            if h.hexdigest() != expected[name]:
                raise ValueError("发布 ZIP 回读校验失败。")
        report = json.loads(bundle.read("verification.json"))
        if (report["manifest_sha256"] != expected["router.manifest"]
                or bundle.read("router.sha256").decode("ascii").split() != [verified["sha256"], "router.qcow2"]):
            raise ValueError("制包期间输入发生变化；发布记录未写入。")
    key = digest(output)
    if record:
        pins = APP / "engine/published-bundles.json"
        index = json.loads(pins.read_text("utf-8"))
        index[key] = {"version": version, "layout": verified["layout"], "report_sha256": verified["report_sha256"]}
        pins.write_text(json.dumps(index, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(key, output)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("version")
    p.add_argument("public_dir", type=Path)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--record", action="store_true", help="把该包的摘要写入程序内的公开发布校验表")
    args = p.parse_args()
    package(args.version, args.public_dir, args.output_dir, args.record)
