"""Node model: a normalised proxy profile independent of the source format."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Node:
    tag: str = ""
    # vless vmess trojan shadowsocks hysteria2 tuic wireguard amneziawg openvpn ikev2 socks http anytls
    type: str = "vless"
    server: str = ""
    port: int = 0
    # credentials
    uuid: str = ""
    password: str = ""
    method: str = ""             # shadowsocks / anytls
    alter_id: int = 0
    security: str = "auto"       # vmess
    flow: str = ""
    # tls
    tls: bool = False
    sni: str = ""
    alpn: list[str] = field(default_factory=list)
    insecure: bool = False
    fingerprint: str = ""        # utls
    reality_pbk: str = ""
    reality_sid: str = ""
    # transport
    transport: str = ""          # "" tcp ws grpc http h2 quic httpupgrade xhttp
    path: str = ""
    host: str = ""
    service_name: str = ""
    grpc_multi: bool = False
    early_data: int = 0
    xhttp_mode: str = ""
    xhttp_extra: dict = field(default_factory=dict)
    # udp-ish protos
    obfs: str = ""
    obfs_password: str = ""
    congestion: str = ""         # tuic
    udp_relay_mode: str = ""     # tuic
    # wireguard
    wg_address: list[str] = field(default_factory=list)
    wg_private_key: str = ""
    wg_peer_public_key: str = ""
    wg_preshared_key: str = ""
    wg_reserved: list[int] = field(default_factory=list)
    wg_mtu: int = 0
    # bookkeeping
    group: str = ""              # subscription name
    remark: str = ""
    enabled: bool = True
    extra: dict = field(default_factory=dict)

    # ----- derived -----
    @property
    def key(self) -> str:
        raw = f"{self.type}|{self.server}|{self.port}|{self.uuid}|{self.password}|{self.transport}|{self.path}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]

    @property
    def supports_udp(self) -> bool:
        """Can this profile carry UDP (needed for Discord voice, games)?"""
        if self.type in ("hysteria2", "tuic", "wireguard", "amneziawg", "openvpn", "ikev2"):
            return True
        if self.transport in ("xhttp", "splithttp"):
            return False
        return True

    @property
    def needs_xray(self) -> bool:
        return self.transport in ("xhttp", "splithttp")

    @property
    def helper(self) -> str:
        """Which extra engine carries this node: xray, mihomo (AmneziaWG), openvpn, ikev2 or '' (sing-box)."""
        if self.needs_xray:
            return "xray"
        if self.type == "amneziawg":
            return "mihomo"
        if self.type in ("openvpn", "ikev2"):
            return self.type
        return ""

    @property
    def is_system_tunnel(self) -> bool:
        return self.type in ("openvpn", "ikev2")

    @property
    def display(self) -> str:
        name = self.remark or f"{self.server}:{self.port}"
        title = {"amneziawg": "AmneziaWG", "openvpn": "OpenVPN", "ikev2": "IKEv2", "wireguard": "WireGuard",
                 "hysteria2": "Hysteria2", "shadowsocks": "Shadowsocks"}.get(self.type, self.type.upper())
        return f"{name}  [{title}{'/' + self.transport.upper() if self.transport else ''}]"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Node":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)
