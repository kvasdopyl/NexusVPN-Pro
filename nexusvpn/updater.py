"""Program self-update from GitHub Releases of the repository the build came from."""
from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from . import build_info, paths
from .cores import NO_WINDOW, _opener

log = logging.getLogger("updater")
API = "https://api.github.com"
ASSET_RE = re.compile(r"setup.*\.exe$", re.I)


class UpdateError(RuntimeError):
    pass


def current_build() -> int:
    return int(build_info.BUILD)


def current_version_text() -> str:
    b = current_build()
    return f"{paths.APP_VERSION} (сборка {b})" if b else f"{paths.APP_VERSION} (своя сборка)"


def parse_build(tag: str) -> int:
    nums = re.findall(r"\d+", tag or "")
    return int(nums[-1]) if nums else 0


def _repo(settings) -> str:
    return (settings["update_repo"] or build_info.REPO).strip().strip("/")


def _headers(settings, accept: str = "application/vnd.github+json") -> dict:
    h = {"User-Agent": "NexusVPN-updater", "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if settings["update_token"].strip():
        h["Authorization"] = f"Bearer {settings['update_token'].strip()}"
    return h


def _open(url: str, headers: dict, proxy_ports: list, timeout: int = 30):
    last: Exception | None = None
    for port in proxy_ports:
        try:
            return _opener(port).open(urllib.request.Request(url, headers=headers), timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404):
                raise UpdateError(_http_hint(e.code)) from e
            last = e
        except OSError as e:
            last = e
    raise UpdateError(f"нет связи с GitHub: {last}")


def _http_hint(code: int) -> str:
    if code == 404:
        return ("релиз не найден. Если репозиторий приватный — сделайте его публичным или впишите токен "
                "(Обновления → Токен GitHub).")
    if code == 401:
        return "токен GitHub недействителен или истёк"
    return "GitHub ограничил число запросов, попробуйте через час"


def latest(settings, proxy_ports: list) -> dict:
    with _open(f"{API}/repos/{_repo(settings)}/releases/latest", _headers(settings), proxy_ports) as r:
        rel = json.loads(r.read())
    asset = next((a for a in rel.get("assets", []) if ASSET_RE.search(a["name"])), None)
    if not asset:
        raise UpdateError(f"в релизе {rel.get('tag_name')} нет установщика")
    digest = asset.get("digest") or ""
    return {"tag": rel["tag_name"], "build": parse_build(rel["tag_name"]), "name": rel.get("name") or rel["tag_name"],
            "notes": (rel.get("body") or "").strip()[:2000], "published": rel.get("published_at", ""),
            "asset": asset["name"], "size": int(asset.get("size", 0)), "api_url": asset["url"],
            "url": asset["browser_download_url"],
            "sha256": digest.split(":", 1)[1] if digest.startswith("sha256:") else ""}


def is_newer(info: dict) -> bool:
    return info.get("build", 0) > current_build()


def download(info: dict, settings, proxy_ports: list, progress=None) -> Path:
    d = paths.RUN_DIR / "updates"
    d.mkdir(parents=True, exist_ok=True)
    for old in d.glob("*.exe"):
        old.unlink(missing_ok=True)
    dest = d / info["asset"]
    tmp = dest.with_suffix(".part")
    # private repos only serve assets through the API endpoint
    url, hdr = (info["api_url"], _headers(settings, "application/octet-stream")) if settings["update_token"].strip() \
        else (info["url"], {"User-Agent": "NexusVPN-updater"})
    sha = hashlib.sha256()
    got = 0
    with _open(url, hdr, proxy_ports, timeout=60) as r, open(tmp, "wb") as fh:
        while chunk := r.read(1 << 16):
            fh.write(chunk)
            sha.update(chunk)
            got += len(chunk)
            if progress:
                progress(got, info["size"])
    if info["size"] and got != info["size"]:
        tmp.unlink(missing_ok=True)
        raise UpdateError("файл скачан не полностью")
    if info["sha256"] and sha.hexdigest() != info["sha256"].lower():
        tmp.unlink(missing_ok=True)
        raise UpdateError("контрольная сумма не совпала — файл повреждён")
    tmp.replace(dest)
    return dest


def is_installed_copy() -> bool:
    return any(paths.BASE_DIR.glob("unins*.exe"))


def run_installer(setup: Path) -> None:
    """Silent upgrade in place; the installer restarts the program when done."""
    subprocess.Popen([str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/UPDATE"],
                     creationflags=NO_WINDOW | 0x00000008)  # DETACHED_PROCESS: survives our exit
