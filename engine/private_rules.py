"""Conservative selections for private LuCI/sysupgrade backups (local processing only)."""
import copy
import io
import json
import os
import posixpath
import re
import shlex
import struct
import tarfile
from pathlib import PurePosixPath


OC = "etc/openclash"
CORE = OC + "/core/clash_meta"
FILTERS = "usr/bin/AdGuardHome/data/filters"
DISABLED = "etc/uci-defaults/10_disable_services"
REQUIRED = ["etc/config/" + n for n in ("network", "firewall", "dhcp", "dropbear", "openclash")]
REQUIRED.append("etc/AdGuardHome.yaml")
ACCOUNT_TABLES = {"etc/passwd", "etc/group", "etc/shadow", "etc/gshadow"}
TREES = set(("etc/config etc/openclash etc/dropbear root/.ssh etc/crontabs etc/dnsmasq.d "
             "etc/nftables.d etc/iproute2 etc/ppp etc/udhcpc.user.d etc/zerotier etc/banip "
             "etc/netdata etc/collectd/conf.d etc/sqm etc/ddns etc/filebrowser etc/wireguard "
             "etc/openvpn etc/ssl/private etc/hotplug.d/ntp").split())
FILES = set(("etc/AdGuardHome.yaml etc/hosts etc/ethers etc/firewall.user etc/dnsmasq.conf "
             "etc/udhcpc.user etc/rc.local etc/passwd etc/group etc/shadow etc/gshadow "
             "etc/shells etc/sysctl.conf etc/uhttpd.key etc/uhttpd.crt etc/zerotier.conf "
             "etc/collectd.conf etc/vnstat.conf etc/profile.user etc/hosts.allow etc/hosts.deny "
             "etc/filebrowser.db").split())
OLD_UCI = {"etc/config/fstab", "etc/config/opkg", "etc/config/adguardhome", "etc/config/luci_app_adguardhome"}
BLOCKED = ("etc/init.d", "etc/rc.d", "etc/uci-defaults", "etc/hotplug.d/block", "etc/opkg",
           "etc/apk", "etc/config/apk", "etc/board.d", "etc/preinit", "etc/modules.d", "etc/modules-boot.d", "etc/ssl/certs",
           "etc/alternatives", "etc/upgrade", "etc/adguardhome", "etc/openwrt_release",
           "etc/openwrt_version", "etc/os-release", "etc/fstab", "etc/sysupgrade.conf",
           "etc/inittab", "etc/hotplug.json", "etc/ld.so.preload")
SERVICES = set("openclash banip ddns miniupnpd sqm zerotier vnstat netdata collectd ttyd filebrowser luci_statistics".split())
REF_OPTIONS = {"path", "addnhosts", "hostsdir", "confdir", "serversfile", "dhcphostsfile",
               "dhcpoptsfile", "dhcp_hostsfile", "conf_file", "private_key_file"}


class Invalid(ValueError):
    pass


class LinkIssues(Invalid):
    def __init__(self, details):
        self.details = list(dict.fromkeys(details))
        super().__init__(f"有 {len(self.details)} 项链接或归档路径需要在本机处理。\n" + self.details[0])


def below(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def invalid_text(s):
    return "\\" in s or any(ord(c) < 32 or ord(c) == 127 for c in s)


def canonical(name):
    if invalid_text(name) or name.startswith("/") or ".." in name.split("/"):
        raise Invalid("备份含不安全的成员路径。")
    return posixpath.normpath(name)


def protected(p):
    low = p.lower()
    return any(below(low, b) for b in OLD_UCI) or any(below(low, b) for b in BLOCKED)


def allowed_extra(p):
    return (p.startswith(("etc/", "root/")) and p == canonical(p)
            and not protected(p))


def chosen(p, extras):
    # Argon backgrounds are served directly by uhttpd. Only carry its media;
    # a newly restored CGI or script must not become public web content.
    if p.startswith("www/luci-static/argon/background/"):
        parent, _, filename = p.rpartition("/")
        return parent == "www/luci-static/argon/background" and filename.lower().endswith(
            (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".mp4", ".webm")
        )
    if below(p, OC + "/core") and p not in (OC + "/core", CORE):
        return False
    return not protected(p) and (p in FILES or any(below(p, t) for t in TREES | extras))


def inventory(tar):
    entries = {}
    for m in tar:
        p = canonical(m.name)
        if p == ".":
            if not m.isdir():
                raise Invalid("备份根条目类型不正确。")
            continue
        if p in entries and not (m.isdir() and entries[p].isdir()):
            raise Invalid("备份含重名条目，无法确定应恢复的版本。")
        entries[p] = m
    return entries


def source_options(tar, m):
    if not m.isfile() or m.size > 4 * 1024**2:
        raise Invalid("需要解析的 UCI 配置须为普通文本文件。")
    section = []
    for line in tar.extractfile(m).read().decode("utf-8", "surrogateescape").splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            # UCI supports multiline quoted strings. Only simple path options are needed.
            continue
        if words and words[0] == "config":
            section = words[1:]
        elif len(words) == 3 and words[0] in ("list", "option"):
            yield section, words[1], words[2]


def script_sources(tar, entries, extras, notices):
    seen = set()
    while True:
        batch = [p for p, m in entries.items() if p not in seen and m.isfile() and chosen(p, extras)
                 and (p.lower().endswith(".sh") or p in ("etc/firewall.user", "etc/rc.local")
                      or (p in extras and not p.lower().endswith((".yaml", ".yml"))))]
        if not batch:
            break
        seen.update(batch)
        for p in batch:
            m = entries[p]
            if m.size > 2 * 1024**2:
                notices.add("较大文件未扫描 shell 引用 /" + p)
                continue
            data = tar.extractfile(m).read()
            if b"\0" in data:
                continue
            for line in data.decode("utf-8", "surrogateescape").splitlines():
                try:
                    lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
                    lexer.whitespace_split = True
                    words = list(lexer)
                except ValueError:
                    continue
                for i, word in enumerate(words[:-1]):
                    if word not in (".", "source") or (i and words[i - 1] not in (";", "&&", "||", "then", "do", "if")):
                        continue
                    ref = words[i + 1]
                    if ref.startswith(("/etc/", "/root/")) and not any(c in ref for c in "$*`?{["):
                        target = canonical(ref[1:])
                        if target in entries and allowed_extra(target):
                            extras.add(target)
                        else:
                            notices.add("需本机核对的 shell 引用 /" + target)
                    elif not ref.startswith(("/lib/", "/usr/lib/", "/usr/share/")):
                        notices.add("脚本含动态或相对 source 路径 /" + p)


def adh_file_sources(tar, config, entries, extras, notices):
    """Recognize file-valued options in AGH's emitted YAML. Do not parse, print
    or fetch credentials, inline keys, subscription URLs or block scalars."""
    if config.size > 4 * 1024**2:
        notices.add("ADH 配置文件较大，请在本机核对本地过滤源、上游文件和证书依赖。")
        return
    sections = {
        "dns": {"upstream_dns_file", "dnscrypt_config_file"},
        "tls": {"certificate_path", "private_key_path"},
        "filters": {"url"},
        "whitelist_filters": {"url"},
    }
    section = ""
    with tar.extractfile(config) as stream:
        for line in stream:
            text = line.decode("utf-8", "surrogateescape").strip("\r\n")
            if text and not text[0].isspace() and text[0] not in "#-":
                section, _, inline = text.partition(":")
                if section in sections and inline.strip().startswith(("{", "[")) and inline.strip() not in ("[]", "{}"):
                    notices.add("ADH 使用内联 YAML，请在本机核对此配置段的外部文件：" + section)
                continue
            if section not in sections:
                continue
            field, separator, value = text.lstrip(" -\t").partition(":")
            if not separator or field not in sections[section]:
                continue
            value = value.strip()
            if value.startswith('"'):
                try:
                    parsed, end = json.JSONDecoder().raw_decode(value)
                    trailing = value[end:].strip()
                    if not isinstance(parsed, str) or (trailing and not trailing.startswith("#")):
                        raise ValueError
                    value = parsed
                except ValueError:
                    notices.add(f"请在本机核对 ADH {section}.{field} 的引用格式。")
                    continue
            elif value.startswith("'"):
                match = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", value)
                if not match:
                    notices.add(f"请在本机核对 ADH {section}.{field} 的引用格式。")
                    continue
                value = match[1].replace("''", "'")
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
            if not value or value in ("~", "null") or value.startswith("#"):
                continue
            if field == "url" and re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) and not value.startswith("file://"):
                continue
            value = value.removeprefix("file://")
            if not value.startswith("/") or value.startswith("//") or invalid_text(value) or ".." in value.split("/"):
                notices.add(f"请在本机核对 ADH {section}.{field} 的非标准本地文件引用。")
                continue
            p = canonical(value[1:])
            member = entries.get(p)
            if allowed_extra(p) and member is not None and (member.isfile() or member.issym() or member.islnk()):
                extras.add(p)
            else:
                notices.add(f"ADH {section}.{field} 引用的本地文件 /{p} 未随配置恢复。请确认新固件已有该文件或取消补备。")


def link_dest(p, m):
    raw = m.linkname
    if not raw or invalid_text(raw):
        raise LinkIssues([f"/{p} → {ascii(raw)}：目标为空或含不安全字符，无法解析。"])
    dest = raw.lstrip("/") if raw.startswith("/") else (
        posixpath.join(posixpath.dirname(p), raw) if m.issym() else raw)
    return posixpath.normpath(dest)


def link_label(p, dest):
    target = dest if dest == ".." or dest.startswith("../") else "/" + dest
    return f"/{p} → {target}"


def checked_links(selected, entries, extras, notices):
    # sysupgrade often records leaves only. An implicit target directory exists
    # only if a retained descendant represents it and the directory itself is
    # inside the restoration scope. Do not overwrite firmware directory modes.
    archive_parents = {str(a) for p in entries for a in PurePosixPath(p).parents}
    implicit = {str(a) for p in selected for a in PurePosixPath(p).parents
                if str(a) not in entries and chosen(str(a), extras)}
    links = {}
    issues = []
    optional = {}
    for p, m in selected.items():
        if p in ACCOUNT_TABLES and not m.isfile():
            issues.append(f"/{p}：账户表须是普通文件，不能以链接或目录覆盖新系统的登录数据库。")
        if p in FILES and m.isdir():
            issues.append(f"/{p}：该配置文件被目录替代，不能覆盖目标系统中的文件。")
        if p in TREES and not m.isdir():
            issues.append(f"/{p}：整个配置目录被文件或链接替代。请在本机备份实际目录内的配置。")
        parent_file = next((str(a) for a in PurePosixPath(p).parents
                            if str(a) in entries and not entries[str(a)].isdir()), None)
        if parent_file:
            issues.append(f"/{p}：上级 /{parent_file} 是文件或链接，不能在其下写入。请核对原备份。")
        if not (m.islnk() or m.issym()):
            if not (m.isfile() or m.isdir()) or m.issparse():
                issues.append(f"/{p}：配置路径含不支持的特殊文件。")
            continue
        if p.startswith("www/luci-static/argon/background/"):
            issues.append(f"/{p}：网页背景必须是普通媒体文件，请将实际图片放入备份。")
            continue
        try:
            dest = link_dest(p, m)
        except LinkIssues as exc:
            issues.extend(exc.details)
            continue
        label = link_label(p, dest)
        if dest.startswith("www/"):
            issues.append(label + "：不能把系统配置链接到网页内容。")
        elif dest in ACCOUNT_TABLES:
            issues.append(label + "：不能将其他配置链接到系统账户表。")
        elif dest == ".." or dest.startswith("../"):
            issues.append(label + "：目标越出归档根目录。请修正原机上的链接后重新备份。")
        elif below(p, OC) != below(dest, OC):
            issues.append(label + "：跨越 OpenClash 恢复边界。请核实原机实际存储位置后重新备份。")
        elif dest in selected or dest in implicit:
            links[p] = dest
        elif dest in entries or dest in archive_parents:
            issues.append(label + "：原备份含目标或其后代，但恢复规则已排除该目标。请在本机核对排除原因。")
        elif (p == OC + "/cache.db" and m.issym() and ".." not in PurePosixPath(m.linkname).parts
              and re.fullmatch(r"etc/openclash/history/[^/]+\.db", dest)
              and all(str(a) not in entries or entries[str(a)].isdir() for a in PurePosixPath(dest).parents)):
            optional[p] = "缺失的缓存数据库"
            notices.add("确认后略过可选的 OpenClash 缓存链接 " + label +
                        "。原备份缺少这份历史数据库。若需保留，请取消并补备目标。")
        elif (p == "etc/ppp/resolv.conf" and m.issym() and m.linkname == "/tmp/resolv.conf.ppp"
              and ("tmp" not in entries or entries["tmp"].isdir())):
            optional[p] = "由新固件提供的 PPP 运行时链接"
            notices.add("确认后沿用新固件 ppp 软件包提供的链接 " + label +
                        "。其目标位于 /tmp，本工具不读取或恢复运行时文件。")
        elif (p == "etc/collectd.conf" and m.issym() and m.linkname == "/var/etc/collectd.conf"
              and ("var" not in entries or entries["var"].isdir()
                   or (entries["var"].issym() and entries["var"].linkname in ("tmp", "/tmp")))
              and ("var/etc" not in entries or entries["var/etc"].isdir())
              and "tmp/etc/collectd.conf" not in entries and "tmp/etc/collectd.conf" not in archive_parents):
            optional[p] = "由 LuCI Statistics 启动时重建的 collectd 配置链接"
            config_note = ("归档中有 /etc/config/luci_statistics，会按恢复规则保留。"
                           if "etc/config/luci_statistics" in selected else
                           "归档未列 /etc/config/luci_statistics，将沿用新固件中的配置。")
            notices.add("确认后由 LuCI Statistics 重建 " + label + "。" + config_note +
                        "服务启动时会重新生成目标；若你手工维护该目标文件，先取消并单独保存自定义配置。")
        else:
            issues.append(label + "：原备份缺少该目标。请在旧机确认实际路径，并将链接与目标一起重新备份。")
    for p in optional:
        selected.pop(p)
    for p, dest in links.items():
        if dest in optional:
            issues.append(link_label(p, dest) + "：该配置依赖" + optional[dest] +
                          "。请核对原机依赖并补备持久化文件，然后重试。")
    for p in links:
        seen = {p}
        dest = links[p]
        while dest in links:
            if dest in seen:
                issues.append(link_label(p, links[p]) + f"：链接链在 /{dest} 处循环。")
                break
            seen.add(dest)
            dest = links[dest]
        if dest not in links and selected[p].islnk():
            if dest not in selected or not selected[dest].isfile():
                issues.append(link_label(p, dest) + "：硬链接的最终目标不是普通文件。")
            else:
                links[p] = dest
    if issues:
        raise LinkIssues(issues)
    return links


def resolve(p, links):
    while p in links:
        p = links[p]
    return p


def disabled_services(tar, m, notices):
    if not m.isfile() or m.size > 128 * 1024:
        raise Invalid("服务状态记录格式异常。")
    try:
        lines = tar.extractfile(m).read().decode("ascii").splitlines()
    except UnicodeError:
        raise Invalid("服务状态记录并非标准 sysupgrade 脚本。") from None
    safe = set()
    ended = False
    for line in map(str.strip, lines):
        if not line:
            continue
        if line == "exit 0" and not ended:
            ended = True
            continue
        match = re.fullmatch(r"/etc/init\.d/([A-Za-z0-9_-]+) disable", line)
        if ended or not match:
            raise Invalid("服务状态文件含非标准命令。请在本地核对或重新导出标准备份。")
        name = match.group(1)
        if name in SERVICES:
            safe.add(name)
        else:
            notices.add("跳过禁用服务 " + name)
    if not ended:
        raise Invalid("服务状态记录缺少标准结束行。")
    return ("".join("/etc/init.d/" + n + " disable\n" for n in sorted(safe)) + "exit 0\n").encode()


def validate_core(tar, member):
    """Check Linux x86-64 load headers without executing the private binary."""
    elf_header = struct.Struct("<16sHHIQQQIHHHHHH")
    program_header = struct.Struct("<IIQQQQQQ")
    error = "OpenClash 核心不是完整的 Linux x86-64 可执行 ELF，请从可用备份补齐。"
    with tar.extractfile(member) as stream:
        data = stream.read(elf_header.size)
        if len(data) != elf_header.size:
            raise Invalid(error)
        ident, kind, machine, version, entry, phoff, _, _, ehsize, phsize, count, *_ = elf_header.unpack(data)
        if (ident[:7] != b"\x7fELF\x02\x01\x01" or kind not in (2, 3) or machine != 62
                or version != 1 or entry == 0 or ehsize != elf_header.size or phsize != program_header.size
                or phoff < elf_header.size or not 0 < count <= 65536 // phsize
                or phoff + count * phsize > member.size):
            raise Invalid(error)
        stream.seek(phoff)
        table = stream.read(count * phsize)
        if len(table) != count * phsize:
            raise Invalid(error)
    executable_entry = False
    for segment, flags, offset, vaddr, _, file_bytes, memory_bytes, align in program_header.iter_unpack(table):
        if segment != 1:  # PT_LOAD
            continue
        if (file_bytes > memory_bytes or offset + file_bytes > member.size
                or (align > 1 and (align & (align - 1) or (vaddr - offset) % align))):
            raise Invalid(error)
        if flags & 1 and vaddr <= entry < vaddr + file_bytes:
            executable_entry = True
    if not executable_entry:
        raise Invalid(error)


def plan(tar, entries, extras, notices, filter_members=()):
    for p in extras:
        if not allowed_extra(p) or not any(below(k, p) for k in entries):
            raise Invalid("--include 的目标须存在于备份中并处于可恢复配置范围。")
    for p in REQUIRED:
        if p not in entries or not entries[p].isfile() or entries[p].size == 0:
            raise Invalid("缺少非空必需文件 /" + p)
        with tar.extractfile(entries[p]) as content:
            prefix = content.read(512 * 1024)
        if b"\0" in prefix or (p.startswith("etc/config/") and
                                 not re.search(rb"(?m)^[ \t]*config[ \t]+[^\s#]+", prefix)):
            raise Invalid("必需文件不是可识别的路由配置 /" + p)
    for name in ("firewall", "dhcp", "network"):
        for section, opt, value in source_options(tar, entries["etc/config/" + name]):
            if opt not in REF_OPTIONS or not value.startswith(("/etc/", "/root/")):
                continue
            if name == "firewall" and (not section or section[0] != "include" or opt != "path"):
                continue
            p = canonical(value[1:].split(",", 1)[0])
            if allowed_extra(p) and (p in entries or any(k.startswith(p + "/") for k in entries)):
                extras.add(p)
            elif not chosen(p, extras) or p not in entries:
                notices.add("需本机确认的 UCI 引用 /" + p)
    script_sources(tar, entries, extras, notices)
    adh_file_sources(tar, entries["etc/AdGuardHome.yaml"], entries, extras, notices)
    selected = {p: m for p, m in entries.items() if chosen(p, extras)}
    core = CORE
    visited = set()
    while core in entries and (entries[core].issym() or entries[core].islnk()):
        if core in visited:
            raise LinkIssues([link_label(core, link_dest(core, entries[core])) + "：OpenClash 核心链接循环。"])
        visited.add(core)
        core = link_dest(core, entries[core])
        if core not in entries or not below(core, OC):
            # checked_links reports the specific path, target and reason.
            break
        selected[core] = entries[core]
    for p, m in list(selected.items()):
        if p != core and m.isfile() and tar.extractfile(m).read(4) == b"\x7fELF":
            selected.pop(p)
    for p, m in entries.items():
        if p not in selected and p not in filter_members and p != DISABLED and not m.isdir():
            notices.add("跳过 /" + p)
    links = checked_links(selected, entries, extras, notices)
    options = [v for sec, opt, v in source_options(tar, entries["etc/config/openclash"])
               if sec == ["openclash", "config"] and opt == "config_path" and v]
    profiles = [p for p in selected if p.startswith(OC + "/config/") and p.lower().endswith((".yaml", ".yml"))
                and (m := selected.get(resolve(p, links))) is not None and m.isfile() and m.size]
    if options:
        candidate = canonical(options[-1].lstrip("/"))
        if candidate not in profiles:
            raise Invalid("OpenClash 的 config_path 对应配置不在备份内，或不是非空 YAML 文件。")
    elif len(profiles) != 1:
        raise Invalid("未找到明确的 OpenClash 活动配置。备份须包含 config_path 指定的 YAML，或唯一的候选 YAML。")
    m = selected.get(resolve(CORE, links))
    if not m or not m.isfile() or not m.mode & 0o111:
        raise Invalid("未找到可执行的 /etc/openclash/core/clash_meta。")
    validate_core(tar, m)
    service_data = disabled_services(tar, entries[DISABLED], notices) if DISABLED in entries else None
    return selected, links, service_data


def owned(name, size, mode, typ=tarfile.REGTYPE):
    m = tarfile.TarInfo(name)
    m.type, m.size, m.mode = typ, size, mode
    m.uname = m.gname = "root"
    return m


def emit(tar, out, selected, links, services, archived_filters, external_files):
    def info(p):
        m = copy.copy(selected[p])
        m.name, m.mode, m.pax_headers = p, m.mode & 0o777, {}
        if p in ACCOUNT_TABLES:
            # Account merging on the target owns the final installation. Never
            # briefly expose hashes or a user-writable account database.
            m.uid = m.gid = 0
            m.uname = m.gname = "root"
            m.mode = 0o600 if p in ("etc/shadow", "etc/gshadow") else 0o644
        if p == "etc/AdGuardHome.yaml":
            m.uid = m.gid = 0
            m.uname = m.gname = "root"
            m.mode = 0o600
        if p.startswith("www/luci-static/argon/background/"):
            m.mode = 0o644
        if not m.isfile():
            m.size = 0
        return m

    for p in sorted(selected, key=lambda x: x.count("/")):
        if selected[p].isdir():
            out.addfile(info(p))
    for p, src in selected.items():
        if src.isfile():
            out.addfile(info(p), tar.extractfile(src))
    for p in sorted(links, key=lambda x: selected[x].issym()):
        m = info(p)
        m.linkname = posixpath.relpath(links[p], posixpath.dirname(p)) if m.issym() else links[p]
        out.addfile(m)
    if services is not None:
        out.addfile(owned(DISABLED, len(services), 0o644), io.BytesIO(services))
    out.addfile(owned(FILTERS, 0, 0o755, tarfile.DIRTYPE))
    for name, src in sorted(archived_filters.items()):
        m = owned(FILTERS + "/" + name, src.size, 0o600)
        m.mtime = src.mtime
        with tar.extractfile(src) as data:
            out.addfile(m, data)
    for p in external_files:
        with p.open("rb") as f:
            st = os.fstat(f.fileno())
            m = owned(FILTERS + "/" + p.name, st.st_size, 0o600)
            m.mtime = int(st.st_mtime)
            out.addfile(m, f)


