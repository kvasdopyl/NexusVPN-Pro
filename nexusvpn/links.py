"""Node -> editable text (share link or config file). Inverse of parsers."""
from __future__ import annotations

import base64
import json
import urllib.parse as up

from .models import Node
from .parsers import parse_link, parse_openvpn, parse_wireguard_conf, ParseError

AWG_CONF_KEYS = {v: k for k, v in {
    "Jc": "jc", "Jmin": "jmin", "Jmax": "jmax", "S1": "s1", "S2": "s2", "S3": "s3", "S4": "s4",
    "H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4", "I1": "i1", "I2": "i2", "I3": "i3", "I4": "i4", "I5": "i5",
    "J1": "j1", "J2": "j2", "J3": "j3", "Itime": "itime",
    "HeaderProtectionKey": "header-protection-key", "ContentPaddingAddition": "content-padding-addition",
    "RekeyAfterTime": "rekey-after-time", "RekeyTimeout": "rekey-timeout", "RejectAfterTime": "reject-after-time",
    "KeepaliveTimeout": "keepalive-timeout", "MaxHandshakeAttempts": "max-handshake-attempts",
    "RandomTrailers": "random-trailers", "DisableCookies": "disable-cookies"}.items()}


def _host(h: str) -> str:
    return f"[{h}]" if ":" in h else h


def _frag(n: Node) -> str:
    return "#" + up.quote(n.remark or n.tag or "", safe="")


def _common_q(n: Node) -> dict:
    q: dict = {}
    if n.reality_pbk:
        q.update(security="reality", pbk=n.reality_pbk, sid=n.reality_sid)
        if n.extra.get("spx"):
            q["spx"] = n.extra["spx"]
    elif n.tls:
        q["security"] = "tls"
    else:
        q["security"] = "none"
    if n.sni:
        q["sni"] = n.sni
    if n.fingerprint:
        q["fp"] = n.fingerprint
    if n.alpn:
        q["alpn"] = ",".join(n.alpn)
    if n.insecure and not n.reality_pbk:
        q["allowInsecure"] = "1"
    q["type"] = n.transport or "tcp"
    if n.path:
        q["path"] = n.path
    if n.host:
        q["host"] = n.host
    if n.service_name:
        q["serviceName"] = n.service_name
    if n.transport in ("xhttp", "splithttp"):
        q["mode"] = n.xhttp_mode or "auto"
        if n.xhttp_extra:
            q["extra"] = json.dumps(n.xhttp_extra, separators=(",", ":"))
    return q


def _qs(q: dict) -> str:
    return up.urlencode({k: v for k, v in q.items() if v not in ("", None)}, quote_via=up.quote)


def wireguard_conf(n: Node) -> str:
    lines = ["[Interface]", f"PrivateKey = {n.wg_private_key}", f"Address = {', '.join(n.wg_address)}"]
    if n.extra.get("dns"):
        lines.append(f"DNS = {', '.join(n.extra['dns'])}")
    if n.wg_mtu:
        lines.append(f"MTU = {n.wg_mtu}")
    for k, v in (n.extra.get("awg") or {}).items():
        if k in AWG_CONF_KEYS:
            lines.append(f"{AWG_CONF_KEYS[k]} = {str(v).lower() if isinstance(v, bool) else v}")
    lines += ["", "[Peer]", f"PublicKey = {n.wg_peer_public_key}"]
    if n.wg_preshared_key:
        lines.append(f"PresharedKey = {n.wg_preshared_key}")
    lines += [f"Endpoint = {_host(n.server)}:{n.port}", "AllowedIPs = 0.0.0.0/0, ::/0",
              f"PersistentKeepalive = {n.extra.get('keepalive', 25)}"]
    return "\n".join(lines) + "\n"


def to_text(n: Node) -> str:
    """Text the user edits: a share link, or a whole config for WireGuard/AmneziaWG/OpenVPN."""
    t = n.type
    if t in ("wireguard", "amneziawg") and (t == "amneziawg" or n.extra.get("conf")):
        return wireguard_conf(n)
    if t == "openvpn":
        return n.extra.get("ovpn", "")
    if t == "vless":
        q = _common_q(n)
        q["encryption"] = "none"
        if n.flow:
            q["flow"] = n.flow
        return f"vless://{n.uuid}@{_host(n.server)}:{n.port}?{_qs(q)}{_frag(n)}"
    if t == "trojan":
        return f"trojan://{up.quote(n.password, safe='')}@{_host(n.server)}:{n.port}?{_qs(_common_q(n))}{_frag(n)}"
    if t == "vmess":
        j = {"v": "2", "ps": n.remark or n.tag, "add": n.server, "port": n.port, "id": n.uuid, "aid": n.alter_id,
             "scy": n.security or "auto", "net": n.transport or "tcp", "type": "none",
             "host": n.host, "path": n.service_name if n.transport == "grpc" else n.path,
             "tls": "tls" if n.tls else "", "sni": n.sni, "alpn": ",".join(n.alpn), "fp": n.fingerprint}
        return "vmess://" + base64.b64encode(json.dumps(j, ensure_ascii=False).encode()).decode()
    if t == "shadowsocks":
        ui = base64.urlsafe_b64encode(f"{n.method}:{n.password}".encode()).decode().rstrip("=")
        plug = f"?plugin={up.quote(n.extra['plugin'], safe='')}" if n.extra.get("plugin") else ""
        return f"ss://{ui}@{_host(n.server)}:{n.port}{plug}{_frag(n)}"
    if t == "hysteria2":
        q = {"sni": n.sni, "insecure": "1" if n.insecure else "", "obfs": n.obfs, "obfs-password": n.obfs_password,
             "alpn": ",".join(n.alpn) if n.alpn and n.alpn != ["h3"] else "", "fp": n.fingerprint}
        if n.extra.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in n.extra["server_ports"])
        return f"hysteria2://{up.quote(n.password, safe='')}@{_host(n.server)}:{n.port}?{_qs(q)}{_frag(n)}"
    if t == "tuic":
        q = {"sni": n.sni, "congestion_control": n.congestion, "udp_relay_mode": n.udp_relay_mode,
             "alpn": ",".join(n.alpn), "allow_insecure": "1" if n.insecure else ""}
        return f"tuic://{n.uuid}:{up.quote(n.password, safe='')}@{_host(n.server)}:{n.port}?{_qs(q)}{_frag(n)}"
    if t == "wireguard":
        q = {"publickey": n.wg_peer_public_key, "address": ",".join(n.wg_address),
             "mtu": n.wg_mtu or "", "presharedkey": n.wg_preshared_key,
             "reserved": ",".join(map(str, n.wg_reserved))}
        return f"wireguard://{up.quote(n.wg_private_key, safe='')}@{_host(n.server)}:{n.port}?{_qs(q)}{_frag(n)}"
    if t in ("socks", "http"):
        scheme = "socks5" if t == "socks" else ("https" if n.tls else "http")
        auth = f"{up.quote(n.uuid, safe='')}:{up.quote(n.password, safe='')}@" if n.uuid else ""
        return f"{scheme}://{auth}{_host(n.server)}:{n.port}{_frag(n)}"
    if t == "anytls":
        return f"anytls://{up.quote(n.password, safe='')}@{_host(n.server)}:{n.port}?{_qs({'sni': n.sni})}{_frag(n)}"
    if t == "ikev2":
        auth = f"{up.quote(n.uuid, safe='')}:{up.quote(n.password, safe='')}@" if n.uuid else ""
        q = {"auth": n.extra.get("auth", "eap"), "strong": "1" if n.extra.get("strong", True) else "0"}
        return f"ikev2://{auth}{_host(n.server)}:{n.port}?{_qs(q)}{_frag(n)}"
    raise ValueError(f"экспорт {t} не поддерживается")


def from_text(text: str, name: str = "", username: str = "", password: str = "") -> Node:
    text = text.strip()
    if "[Interface]" in text:
        n = parse_wireguard_conf(text, name or "WireGuard")
    elif "://" in text.split("\n", 1)[0] and "\n" not in text:
        n = parse_link(text)
    elif "remote" in text:
        n = parse_openvpn(text, name or "OpenVPN", username, password)
    else:
        raise ParseError("Не удалось распознать: нужна ссылка, .conf WireGuard/AmneziaWG или .ovpn")
    if name:
        n.remark = name
    return n
