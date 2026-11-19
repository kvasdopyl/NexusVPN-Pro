"""Minimal client for the sing-box Clash-compatible REST API."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


class ClashAPI:
    def __init__(self, port: int, secret: str):
        self.base = f"http://127.0.0.1:{port}"
        self.secret = secret
        # the API is on loopback: never route these requests through a system proxy
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _req(self, method: str, path: str, body: dict | None = None, timeout: float = 5):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.secret}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with self._opener.open(req, timeout=timeout) as r:
            raw = r.read()
        return json.loads(raw) if raw else None

    def alive(self) -> bool:
        try:
            return bool(self._req("GET", "/version", timeout=2))
        except (OSError, ValueError):
            return False

    def version(self) -> str:
        return (self._req("GET", "/version") or {}).get("version", "")

    def connections(self) -> dict:
        return self._req("GET", "/connections") or {}

    def close_connection(self, cid: str) -> None:
        self._req("DELETE", f"/connections/{urllib.parse.quote(cid)}")

    def close_all(self) -> None:
        self._req("DELETE", "/connections")

    def proxies(self) -> dict:
        return (self._req("GET", "/proxies") or {}).get("proxies", {})

    def select(self, group: str, name: str) -> None:
        self._req("PUT", f"/proxies/{urllib.parse.quote(group)}", {"name": name})

    def now(self, group: str) -> str:
        """Which member a selector/urltest group currently uses ('' if unknown)."""
        try:
            return (self._req("GET", f"/proxies/{urllib.parse.quote(group)}") or {}).get("now", "") or ""
        except (OSError, ValueError):
            return ""

    def delay(self, name: str, url: str, timeout_ms: int = 5000) -> int:
        q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
        try:
            r = self._req("GET", f"/proxies/{urllib.parse.quote(name)}/delay?{q}", timeout=timeout_ms / 1000 + 2)
            return int((r or {}).get("delay", -1))
        except urllib.error.HTTPError:
            return -1
        except (OSError, ValueError):
            return -1

    def group_delay(self, group: str, url: str, timeout_ms: int = 5000) -> dict[str, int]:
        q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
        try:
            return self._req("GET", f"/group/{urllib.parse.quote(group)}/delay?{q}", timeout=timeout_ms / 1000 + 5) or {}
        except (OSError, ValueError):
            return {}

    def stream(self, path: str, timeout: float = 10):
        """Yield JSON objects from a streaming endpoint (/traffic, /memory, /logs)."""
        req = urllib.request.Request(self.base + path)
        req.add_header("Authorization", f"Bearer {self.secret}")
        with self._opener.open(req, timeout=timeout) as r:
            for line in r:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
