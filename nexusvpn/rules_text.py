"""Batch rule lists: one entry per line, typed or pasted by the user."""
from __future__ import annotations

import ipaddress
import re

KINDS_HELP = """Одна запись на строку (можно вставить сразу сотни строк):
  example.com        — домен и все его поддомены
  *.example.com      — то же самое
  full:api.site.com  — только этот адрес, без поддоменов
  keyword:google     — все домены, содержащие слово
  1.2.3.4            — один IP
  10.0.0.0/8         — подсеть (CIDR), IPv4 или IPv6
  Telegram.exe       — программа (только в режиме TUN)
  # комментарий      — строки с # игнорируются
Ссылки (https://site.com/path) автоматически превращаются в домен."""

_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def parse_line(raw: str) -> tuple[str, str] | None:
    """-> (kind, value) or None for blank/comment. Raises ValueError on garbage."""
    s = raw.split("#", 1)[0].strip().strip(",;")
    if not s:
        return None
    low = s.lower()
    if low.startswith("full:"):
        v = low[5:].strip()
        if not _DOMAIN.match(v):
            raise ValueError("неверный домен")
        return "full", v
    if low.startswith("keyword:"):
        v = low[8:].strip()
        if not v or " " in v:
            raise ValueError("пустое ключевое слово")
        return "keyword", v
    if low.startswith("domain:"):
        low = low[7:].strip()
    if low.endswith(".exe"):
        return "process", s.replace("/", "\\").rsplit("\\", 1)[-1]
    try:
        net = ipaddress.ip_network(s, strict=False)
        return "ip", str(net) if "/" in s else net.network_address.compressed + ("/128" if net.version == 6 else "/32")
    except ValueError:
        pass
    low = re.sub(r"^[a-z][a-z0-9+.-]*://", "", low)
    low = low.split("/", 1)[0].split("?", 1)[0]
    low = re.sub(r":\d+$", "", low)
    low = low.lstrip("*").lstrip(".").rstrip(".")
    if low.startswith("www.") and low.count(".") >= 2:
        low = low[4:]
    if _DOMAIN.match(low):
        return "domain", low
    raise ValueError("не похоже на домен, IP, подсеть или .exe")


def parse_text(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    entries: list[tuple[str, str]] = []
    errors: list[str] = []
    seen = set()
    for i, line in enumerate(text.splitlines(), 1):
        body = line.split("#", 1)[0].strip()
        # a Windows path may contain spaces: keep it whole
        parts = [body] if body.lower().endswith(".exe") and ("\\" in body or "/" in body) \
            else re.split(r"[\s,;]+", body)
        for part in parts:
            if not part:
                continue
            try:
                e = parse_line(part)
            except ValueError as ex:
                errors.append(f"строка {i}: «{part}» — {ex}")
                continue
            if e and e not in seen:
                seen.add(e)
                entries.append(e)
    return entries, errors


def to_text(entries: list[tuple[str, str]]) -> str:
    order = {"domain": 0, "full": 1, "keyword": 2, "ip": 3, "process": 4}
    out = []
    for kind, v in sorted(entries, key=lambda e: (order.get(e[0], 9), e[1])):
        if kind == "full":
            out.append(f"full:{v}")
        elif kind == "keyword":
            out.append(f"keyword:{v}")
        elif kind == "ip" and ((":" not in v and v.endswith("/32")) or (":" in v and v.endswith("/128"))):
            out.append(v.rsplit("/", 1)[0])
        else:
            out.append(v)
    return "\n".join(out)
