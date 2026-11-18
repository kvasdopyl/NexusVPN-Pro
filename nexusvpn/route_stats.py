"""Running totals of traffic split by route (VPN / direct), built from the core's /connections."""
from __future__ import annotations

import re

from .learner import base_domain

_IP = re.compile(r"^[\d.]+$|:")


def _service(md: dict) -> str:
    host = (md.get("host") or "").strip(".").lower()
    if host and not _IP.search(host):
        return base_domain(host)
    proc = re.sub(r" \(.*\)$", "", md.get("processPath") or "").replace("/", "\\").rsplit("\\", 1)[-1]
    if proc:
        return proc
    return md.get("destinationIP") or host or "?"


class RouteStats:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._live: dict[str, tuple[bool, int, str]] = {}   # id -> (via_vpn, bytes, service)
        self._closed = {True: 0, False: 0}
        self._by_service: dict[str, int] = {}

    def update(self, conns: list[dict]) -> dict:
        live: dict[str, tuple[bool, int, str]] = {}
        for c in conns:
            cid = c.get("id")
            chains = c.get("chains") or []
            if not cid or not chains:
                continue
            md = c.get("metadata") or {}
            if "probe-" in str(md.get("type", "")):
                continue
            vpn = chains[0] != "direct"
            live[cid] = (vpn, int(c.get("upload", 0)) + int(c.get("download", 0)), _service(md))
        for cid, (vpn, b, _svc) in self._live.items():
            if cid not in live:
                self._closed[vpn] += b
        for cid, (vpn, b, svc) in live.items():
            if vpn:
                prev = self._live.get(cid, (True, 0, svc))[1]
                self._by_service[svc] = self._by_service.get(svc, 0) + max(0, b - prev)
        self._live = live
        if len(self._by_service) > 500:
            self._by_service = dict(sorted(self._by_service.items(), key=lambda kv: -kv[1])[:200])
        now_vpn = sorted({svc for vpn, _b, svc in live.values() if vpn})
        return {
            "vpn_conns": sum(1 for v, _, _ in live.values() if v),
            "direct_conns": sum(1 for v, _, _ in live.values() if not v),
            "vpn_bytes": self._closed[True] + sum(b for v, b, _ in live.values() if v),
            "direct_bytes": self._closed[False] + sum(b for v, b, _ in live.values() if not v),
            "vpn_now": now_vpn,
            "top_vpn": sorted(self._by_service.items(), key=lambda kv: -kv[1])[:6],
        }
