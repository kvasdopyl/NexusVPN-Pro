"""Download / update / roll back the proxy cores and rule databases."""
from __future__ import annotations

import io
import json
import logging
import platform
import re
import shutil
import ssl
import subprocess
import tarfile
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from . import paths
from .presets import ALL_TAGS

log = logging.getLogger("cores")
NO_WINDOW = 0x08000000 if paths.EXE else 0


@dataclass
class CoreSpec:
    name: str
    repo: str
    asset_re: str          # regex for the release asset of this platform
    version_args: list[str]
    version_re: str
    required: bool


def _arch() -> str:
    m = platform.machine().lower()
    return "arm64" if m in ("arm64", "aarch64") else "amd64"


def _specs() -> dict[str, CoreSpec]:
    win = bool(paths.EXE)
    a = _arch()
    xr_arch = {"amd64": "64", "arm64": "arm64-v8a"}[a]
    return {
        "sing-box": CoreSpec(
            "sing-box", "SagerNet/sing-box",
            rf"sing-box-[\d.]+-windows-{a}\.zip$" if win else rf"sing-box-[\d.]+-linux-{a}\.tar\.gz$",
            ["version"], r"sing-box version ([\w.\-]+)", True),
        "xray": CoreSpec(
            "xray", "XTLS/Xray-core",
            rf"Xray-windows-{xr_arch}\.zip$" if win else rf"Xray-linux-{xr_arch}\.zip$",
            ["version"], r"Xray ([\w.\-]+)", False),
        # "compatible" builds run on any x86-64 CPU (no AVX requirement)
        "mihomo": CoreSpec(
            "mihomo", "MetaCubeX/mihomo",
            (rf"mihomo-windows-{a}-compatible-v[\d.]+\.zip$" if a == "amd64" else rf"mihomo-windows-{a}-v[\d.]+\.zip$")
            if win else
            (rf"mihomo-linux-{a}-compatible-v[\d.]+\.gz$" if a == "amd64" else rf"mihomo-linux-{a}-v[\d.]+\.gz$"),
            ["-v"], r"Mihomo Meta v?([\w.\-]+)", False),
    }


SPECS = _specs()


def _opener(proxy_port: int | None):
    handlers: list = [urllib.request.HTTPSHandler(context=ssl.create_default_context())]
    if proxy_port:
        p = f"http://127.0.0.1:{proxy_port}"
        handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)


def http_get(url: str, proxy_ports: list[int | None], timeout: int = 60, accept: str = "*/*") -> bytes:
    """Try direct first, then each proxy port. GitHub is throttled on some ISPs."""
    last: Exception | None = None
    for port in proxy_ports:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NexusVPN-updater", "Accept": accept})
            with _opener(port).open(req, timeout=timeout) as r:
                return r.read()
        except OSError as e:
            last = e
            log.warning("GET %s via %s failed: %s", url, port or "direct", e)
    raise OSError(f"не удалось скачать {url}: {last}")


def installed_version(name: str) -> str:
    spec = SPECS[name]
    exe = paths.core_path(name)
    if not exe.exists():
        return ""
    try:
        out = subprocess.run([str(exe), *spec.version_args], capture_output=True, text=True, timeout=10,
                             creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.SubprocessError):
        return "?"
    m = re.search(spec.version_re, out)
    return m.group(1).lstrip("v") if m else "?"


def latest_release(name: str, proxy_ports: list[int | None], prerelease: bool = False) -> tuple[str, str]:
    """Return (version, asset_download_url)."""
    spec = SPECS[name]
    api = f"https://api.github.com/repos/{spec.repo}/releases"
    data = json.loads(http_get(api + ("?per_page=15" if prerelease else "/latest"), proxy_ports, 30,
                               "application/vnd.github+json"))
    releases = data if isinstance(data, list) else [data]
    for rel in releases:
        if rel.get("draft") or (rel.get("prerelease") and not prerelease):
            continue
        for a in rel.get("assets", []):
            if re.search(spec.asset_re, a["name"]):
                return rel["tag_name"].lstrip("v"), a["browser_download_url"]
    raise OSError(f"для {name} не найден файл под эту платформу")


def _extract(name: str, blob: bytes, url: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    exe_name = f"{name}{paths.EXE}"
    if url.endswith(".gz") and not url.endswith(".tar.gz"):
        import gzip
        (dest / exe_name).write_bytes(gzip.decompress(blob))
        (dest / exe_name).chmod(0o755)
    elif url.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                if not base or info.is_dir():
                    continue
                low = base.lower()
                # mihomo ships as e.g. mihomo-windows-amd64-compatible.exe
                if low.startswith(name) and low.endswith(".exe") and low != exe_name.lower():
                    base = exe_name
                    low = base.lower()
                # binary + dlls (libcronet etc.) + xray geo files
                if low == exe_name.lower() or low.endswith((".dll", ".dat")):
                    (dest / base).write_bytes(z.read(info))
                    (dest / base).chmod(0o755)
    else:
        with tarfile.open(fileobj=io.BytesIO(blob)) as t:
            for m in t.getmembers():
                base = m.name.rsplit("/", 1)[-1]
                if m.isfile() and (base == exe_name or base.endswith(".so")):
                    f = t.extractfile(m)
                    if f:
                        (dest / base).write_bytes(f.read())
                        (dest / base).chmod(0o755)
    if not (dest / exe_name).exists():
        raise OSError(f"в архиве нет {exe_name}")


def install(name: str, proxy_ports: list[int | None], version_url: tuple[str, str] | None = None,
            before_replace=None) -> str:
    """Download and atomically replace a core; previous build goes to backup/ for rollback."""
    ver, url = version_url or latest_release(name, proxy_ports)
    blob = http_get(url, proxy_ports, timeout=300)
    staging = paths.CORES_DIR / f".{name}.new"
    shutil.rmtree(staging, ignore_errors=True)
    _extract(name, blob, url, staging)
    # smoke test the new binary before swapping it in
    r = subprocess.run([str(staging / f"{name}{paths.EXE}"), *SPECS[name].version_args],
                       capture_output=True, text=True, timeout=15, creationflags=NO_WINDOW)
    if r.returncode != 0:
        shutil.rmtree(staging, ignore_errors=True)
        raise OSError(f"новый {name} не запускается: {r.stderr[:200]}")
    if before_replace:
        before_replace()
    target = paths.CORES_DIR / name
    backup = paths.BACKUP_DIR / name
    if target.exists():
        shutil.rmtree(backup, ignore_errors=True)
        for _ in range(10):   # Windows keeps the file locked a moment after the process exits
            try:
                shutil.move(str(target), str(backup))
                break
            except OSError:
                time.sleep(0.5)
    shutil.move(str(staging), str(target))
    log.info("%s updated to %s", name, ver)
    return ver


def rollback(name: str) -> bool:
    backup = paths.BACKUP_DIR / name
    if not backup.exists():
        return False
    target = paths.CORES_DIR / name
    tmp = paths.CORES_DIR / f".{name}.old"
    shutil.rmtree(tmp, ignore_errors=True)
    if target.exists():
        shutil.move(str(target), str(tmp))
    shutil.move(str(backup), str(target))
    if tmp.exists():
        shutil.move(str(tmp), str(backup))
    return True


def update_rules(proxy_ports: list[int | None], tags: list[str] | None = None) -> dict[str, str]:
    """Download .srs rule-sets. Returns {tag: 'ok' | error}."""
    out = {}
    for tag in tags or list(ALL_TAGS):
        url = ALL_TAGS[tag]
        try:
            blob = http_get(url, proxy_ports, timeout=120)
            if len(blob) < 16:
                raise OSError("пустой файл")
            f = paths.RULES_DIR / f"{tag}.srs"
            tmp = f.with_suffix(".tmp")
            tmp.write_bytes(blob)
            tmp.replace(f)   # sing-box reloads local rule-sets on change
            out[tag] = "ok"
        except OSError as e:
            out[tag] = str(e)
    return out


def missing_rules(tags: list[str]) -> list[str]:
    return [t for t in tags if not (paths.RULES_DIR / f"{t}.srs").exists()]


def rules_age_days() -> float:
    files = list(paths.RULES_DIR.glob("*.srs"))
    if not files:
        return 1e9
    return (time.time() - min(f.stat().st_mtime for f in files)) / 86400


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)[:4])


def is_newer(latest: str, current: str) -> bool:
    if not current or current == "?":
        return True
    return _vkey(latest) > _vkey(current)


# ---------------------------------------------------------------- OpenVPN (system component, Windows)
def openvpn_latest(proxy_ports: list[int | None]) -> tuple[str, str]:
    """(version, msi_url) of the newest OpenVPN community build for this CPU."""
    tags = json.loads(http_get("https://api.github.com/repos/OpenVPN/openvpn/tags?per_page=30", proxy_ports, 30))
    versions = sorted({t["name"].lstrip("v") for t in tags if re.fullmatch(r"v\d+\.\d+\.\d+", t["name"])},
                      key=_vkey, reverse=True)
    arch = _arch()
    for ver in versions[:4]:
        for i in range(5, 0, -1):
            url = f"https://swupdate.openvpn.net/community/releases/OpenVPN-{ver}-I00{i}-{arch}.msi"
            try:
                req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "NexusVPN-updater"})
                for port in proxy_ports:
                    try:
                        with _opener(port).open(req, timeout=15) as r:
                            if r.status == 200:
                                return ver, url
                    except OSError:
                        continue
            except ValueError:
                continue
    raise OSError("не найден установщик OpenVPN")


def install_openvpn(proxy_ports: list[int | None]) -> str:
    """Silent install of the official OpenVPN MSI (driver + openvpn.exe)."""
    if not paths.EXE:
        raise OSError("установка OpenVPN доступна только в Windows")
    ver, url = openvpn_latest(proxy_ports)
    msi = paths.RUN_DIR / url.rsplit("/", 1)[-1]
    msi.write_bytes(http_get(url, proxy_ports, timeout=600))
    r = subprocess.run(["msiexec", "/i", str(msi), "/qn", "/norestart"], capture_output=True, text=True,
                       timeout=900, creationflags=NO_WINDOW)
    msi.unlink(missing_ok=True)
    if r.returncode not in (0, 3010):
        raise OSError(f"установщик OpenVPN вернул код {r.returncode}")
    return ver
