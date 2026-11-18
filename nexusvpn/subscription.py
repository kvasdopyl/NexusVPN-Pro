"""Subscription download, node storage and periodic refresh."""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.request
from dataclasses import dataclass, asdict

from .models import Node
from .parsers import parse_subscription
from .paths import NODES_FILE

USER_AGENTS = ["v2rayN/7.0", "sing-box/1.14.4", "clash-verge/2.0", "NexusVPN/2.0"]


@dataclass
class Subscription:
    name: str
    url: str
    enabled: bool = True
    insecure: bool = True           # 3x-ui panels usually run on a self-signed cert
    user_agent: str = "v2rayN/7.0"
    via_proxy: bool = False
    updated_at: float = 0
    upload: int = 0
    download: int = 0
    total: int = 0
    expire: int = 0
    interval_hours: int = 0         # 0 = use server header / global setting
    last_error: str = ""
    count: int = 0

    @classmethod
    def from_dict(cls, d: dict) -> "Subscription":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def _parse_userinfo(h: str) -> dict[str, int]:
    out = {}
    for k, v in re.findall(r"(\w+)=(\d+)", h or ""):
        out[k] = int(v)
    return out


def fetch(sub: Subscription, proxy_port: int | None = None, timeout: int = 25) -> tuple[list[Node], list[str]]:
    ctx = ssl.create_default_context()
    if sub.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    handlers: list = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy_port:
        p = f"http://127.0.0.1:{proxy_port}"
        handlers.append(urllib.request.ProxyHandler({"http": p, "https": p}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(sub.url, headers={"User-Agent": sub.user_agent or USER_AGENTS[0],
                                                   "Accept": "*/*"})
    with opener.open(req, timeout=timeout) as r:
        body = r.read(20 * 1024 * 1024)
        info = _parse_userinfo(r.headers.get("Subscription-Userinfo", ""))
        interval = r.headers.get("Profile-Update-Interval", "")
    sub.upload = info.get("upload", 0)
    sub.download = info.get("download", 0)
    sub.total = info.get("total", 0)
    sub.expire = info.get("expire", 0)
    if interval.isdigit() and not sub.interval_hours:
        sub.interval_hours = int(interval)
    nodes, warns = parse_subscription(body, group=sub.name)
    sub.updated_at = time.time()
    sub.count = len(nodes)
    sub.last_error = ""
    return nodes, warns


class NodeStore:
    """Holds nodes from all subscriptions plus manual ones."""

    MANUAL = "Ручные"

    def __init__(self, path=NODES_FILE):
        self.path = path
        self.nodes: list[Node] = []
        self.load()

    def load(self) -> None:
        try:
            self.nodes = [Node.from_dict(d) for d in json.loads(self.path.read_text("utf-8"))]
        except (OSError, ValueError):
            self.nodes = []

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps([n.to_dict() for n in self.nodes], ensure_ascii=False, indent=1), "utf-8")
        tmp.replace(self.path)

    def replace_group(self, group: str, nodes: list[Node]) -> None:
        prev = {n.key: n for n in self.nodes if n.group == group}
        for n in nodes:
            if n.key in prev:
                n.enabled = prev[n.key].enabled
        self.nodes = [n for n in self.nodes if n.group != group] + nodes
        self._uniq_tags()
        self.save()

    def add_nodes(self, nodes: list[Node]) -> None:
        for n in nodes:
            n.group = self.MANUAL
            n.tag = n.tag or n.remark or f"{n.type}-{n.server}"
        self.nodes.extend(nodes)
        self._uniq_tags()
        self.save()

    def update_node(self, old_tag: str, new: Node) -> Node:
        """Replace a node in place (edit dialog). Edited subscription nodes become manual ones,
        otherwise the next subscription refresh would silently undo the edit."""
        for i, n in enumerate(self.nodes):
            if n.tag == old_tag:
                new.enabled = n.enabled
                new.group = self.MANUAL
                new.tag = new.remark or old_tag
                self.nodes[i] = new
                break
        else:
            raise KeyError(old_tag)
        self._uniq_tags()
        self.save()
        return new

    def remove(self, tags: set[str]) -> None:
        self.nodes = [n for n in self.nodes if n.tag not in tags]
        self.save()

    def remove_group(self, group: str) -> None:
        self.nodes = [n for n in self.nodes if n.group != group]
        self.save()

    def enabled(self) -> list[Node]:
        return [n for n in self.nodes if n.enabled]

    def by_tag(self, tag: str) -> Node | None:
        return next((n for n in self.nodes if n.tag == tag), None)

    def _uniq_tags(self) -> None:
        reserved = {"proxy", "direct", "auto", "discord", "block", "probe-proxy", "probe-direct", "auto-udp"}
        seen: set[str] = set()
        for n in self.nodes:
            base = (n.tag or n.remark or n.server).strip() or "node"
            tag, i = base, 2
            while tag in seen or tag in reserved:
                tag = f"{base} #{i}"
                i += 1
            n.tag = tag
            seen.add(tag)


def subs_from_settings(settings) -> list[Subscription]:
    return [Subscription.from_dict(d) for d in settings.get("subscriptions", [])]


def subs_to_settings(settings, subs: list[Subscription]) -> None:
    settings.set("subscriptions", [asdict(s) for s in subs])
    settings.save()
