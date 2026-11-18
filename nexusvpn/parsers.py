"""Parsers for share links and subscription bodies.

Supported: vless, vmess, trojan, ss (SIP002 + legacy + SS2022), hysteria2/hy2,
tuic, wireguard/wg, socks/socks5, http/https, anytls; base64 / plain lists,
Clash/Mihomo YAML, sing-box JSON, WireGuard .conf.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse as up
from typing import Iterable

from .models import Node

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


class ParseError(ValueError):
    pass


# ---------------------------------------------------------------- helpers
def b64decode_loose(s: str) -> bytes:
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_"))
    except (binascii.Error, ValueError) as e:
        raise ParseError(f"bad base64: {e}") from e


def _q(query: str) -> dict[str, str]:
    # keys (WireGuard, Reality) contain raw "+" which parse_qs would turn into spaces
    return {k: v[0] for k, v in up.parse_qs(query.replace("+", "%2B"), keep_blank_values=True).items()}


def _bool(v) -> bool:
    return str(v).lower() in ("1", "true", "yes", "on")


def _alpn(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return [x.strip() for x in str(v).split(",") if x.strip()]


def _host_port(netloc: str) -> tuple[str, int]:
    u = up.urlsplit("//" + netloc)
    if not u.hostname or not u.port:
        raise ParseError(f"no host/port in {netloc!r}")
    return u.hostname, u.port


def _fragment(u: up.SplitResult) -> str:
    return up.unquote(u.fragment or "").strip()


def _apply_transport(n: Node, q: dict[str, str]) -> None:
    t = (q.get("type") or q.get("net") or "tcp").lower()
    if t == "tcp" and q.get("headerType") == "http":
        t = "http"
    n.transport = "" if t in ("tcp", "raw", "") else t
    n.path = up.unquote(q.get("path", "") or "")
    n.host = q.get("host", "") or q.get("authority", "")
    n.service_name = up.unquote(q.get("serviceName", "") or q.get("service_name", "") or "")
    n.grpc_multi = q.get("mode", "") == "multi" and t == "grpc"
    if t in ("xhttp", "splithttp"):
        n.xhttp_mode = q.get("mode", "auto") or "auto"
        if q.get("extra"):
            try:
                n.xhttp_extra = json.loads(q["extra"])
            except ValueError:
                n.xhttp_extra = {}
    m = re.search(r"[?&]ed=(\d+)", n.path)
    if m and n.transport == "ws":
        n.early_data = int(m.group(1))
        n.path = re.sub(r"[?&]ed=\d+", "", n.path)


def _apply_tls(n: Node, q: dict[str, str], default_tls: bool = False) -> None:
    sec = (q.get("security") or ("tls" if default_tls else "none")).lower()
    n.tls = sec in ("tls", "reality", "xtls")
    n.sni = q.get("sni") or q.get("peer") or q.get("serverName") or ""
    n.alpn = _alpn(q.get("alpn"))
    n.fingerprint = q.get("fp", "") or q.get("fingerprint", "")
    n.insecure = _bool(q.get("allowInsecure") or q.get("insecure") or q.get("allow_insecure") or "0")
    if sec == "reality":
        n.reality_pbk = q.get("pbk", "")
        n.reality_sid = q.get("sid", "")
        if q.get("spx"):
            n.extra["spx"] = up.unquote(q["spx"])
        if not n.fingerprint:
            n.fingerprint = "chrome"
    # sni pointing to a bare IP almost always means a self-signed panel cert
    if n.tls and not n.reality_pbk and re.fullmatch(r"[\d.]+|\[?[0-9a-fA-F:]+\]?", n.sni or n.server or ""):
        n.insecure = True


# ---------------------------------------------------------------- per scheme
def parse_vless(link: str) -> Node:
    u = up.urlsplit(link)
    q = _q(u.query)
    host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
    n = Node(type="vless", server=host, port=port, uuid=up.unquote(u.username or ""),
             remark=_fragment(u), flow=q.get("flow", ""))
    _apply_transport(n, q)
    _apply_tls(n, q)
    return n


def parse_trojan(link: str) -> Node:
    u = up.urlsplit(link)
    q = _q(u.query)
    host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
    n = Node(type="trojan", server=host, port=port, password=up.unquote(u.username or ""),
             remark=_fragment(u))
    _apply_transport(n, q)
    _apply_tls(n, q, default_tls=True)
    return n


def parse_vmess(link: str) -> Node:
    body = link[len("vmess://"):]
    try:
        j = json.loads(b64decode_loose(body.split("#")[0]))
    except (ParseError, ValueError):
        # vmess://uuid@host:port?... (ducksoft / v2rayN alt format)
        u = up.urlsplit(link)
        q = _q(u.query)
        host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
        n = Node(type="vmess", server=host, port=port, uuid=up.unquote(u.username or ""),
                 security=q.get("encryption", "auto"), remark=_fragment(u))
        _apply_transport(n, q)
        _apply_tls(n, q)
        return n
    q = {
        "type": j.get("net", "tcp"), "path": j.get("path", ""), "host": j.get("host", ""),
        "serviceName": j.get("path", "") if j.get("net") == "grpc" else "",
        "headerType": j.get("type", ""), "security": j.get("tls", "") or "none",
        "sni": j.get("sni", ""), "alpn": j.get("alpn", ""), "fp": j.get("fp", ""),
        "allowInsecure": str(j.get("allowInsecure", j.get("skip-cert-verify", "0"))),
        "pbk": j.get("pbk", ""), "sid": j.get("sid", ""), "mode": j.get("mode", ""),
    }
    if q["type"] == "grpc":
        q["path"] = ""
    n = Node(type="vmess", server=str(j.get("add", "")), port=int(j.get("port", 0)),
             uuid=str(j.get("id", "")), alter_id=int(j.get("aid", 0) or 0),
             security=j.get("scy", "auto") or "auto", remark=str(j.get("ps", "")))
    _apply_transport(n, q)
    _apply_tls(n, q)
    if not n.sni and n.tls:
        n.sni = n.host
    return n


def parse_ss(link: str) -> Node:
    body = link[len("ss://"):]
    remark = ""
    if "#" in body:
        body, remark = body.split("#", 1)
        remark = up.unquote(remark)
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    plugin = _q(query).get("plugin", "")
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = up.unquote(userinfo)
        if ":" not in userinfo:
            userinfo = b64decode_loose(userinfo).decode()
    else:  # legacy: base64(method:pass@host:port)
        dec = b64decode_loose(body).decode()
        userinfo, hostport = dec.rsplit("@", 1)
    method, password = userinfo.split(":", 1)
    host, port = _host_port(hostport.split("/")[0])
    n = Node(type="shadowsocks", server=host, port=port, method=method, password=password, remark=remark)
    if plugin:
        n.extra["plugin"] = plugin
    return n


def parse_hysteria2(link: str) -> Node:
    u = up.urlsplit(link.replace("hy2://", "hysteria2://", 1))
    q = _q(u.query)
    netloc = u.netloc.rsplit("@", 1)[-1]
    # port hopping "host:443,20000-30000" -> first port, keep the range
    m = re.match(r"^(\[.*\]|[^:]+):([\d,\-]+)$", netloc)
    if not m:
        raise ParseError("bad hysteria2 host")
    ports = m.group(2)
    first = int(re.split(r"[,-]", ports)[0])
    pw = up.unquote(u.username or "")
    if u.password:
        pw += ":" + up.unquote(u.password)
    n = Node(type="hysteria2", server=m.group(1).strip("[]"), port=first, password=pw,
             remark=_fragment(u), obfs=q.get("obfs", ""), obfs_password=q.get("obfs-password", ""))
    if ports != str(first):
        n.extra["server_ports"] = [p.replace("-", ":") for p in ports.split(",")]
    if q.get("mport"):
        n.extra["server_ports"] = [p.replace("-", ":") for p in q["mport"].split(",")]
    _apply_tls(n, q, default_tls=True)
    n.tls = True
    if not n.alpn:
        n.alpn = ["h3"]
    if q.get("upmbps") or q.get("up"):
        n.extra["up_mbps"] = int(re.sub(r"\D", "", q.get("upmbps") or q.get("up")) or 0)
    if q.get("downmbps") or q.get("down"):
        n.extra["down_mbps"] = int(re.sub(r"\D", "", q.get("downmbps") or q.get("down")) or 0)
    return n


def parse_tuic(link: str) -> Node:
    u = up.urlsplit(link)
    q = _q(u.query)
    host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
    n = Node(type="tuic", server=host, port=port, uuid=up.unquote(u.username or ""),
             password=up.unquote(u.password or ""), remark=_fragment(u),
             congestion=q.get("congestion_control", "bbr"), udp_relay_mode=q.get("udp_relay_mode", "native"))
    _apply_tls(n, q, default_tls=True)
    n.tls = True
    if not n.alpn:
        n.alpn = ["h3"]
    return n


def parse_wireguard(link: str) -> Node:
    u = up.urlsplit(link.replace("wg://", "wireguard://", 1))
    q = _q(u.query)
    host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
    addr = [a.strip() for a in (q.get("address") or q.get("ip") or "").split(",") if a.strip()]
    addr = [a if "/" in a else (a + ("/128" if ":" in a else "/32")) for a in addr]
    reserved = [int(x) for x in re.split(r"[,\s]+", q.get("reserved", "")) if x.strip().isdigit()]
    n = Node(type="wireguard", server=host, port=port, remark=_fragment(u),
             wg_private_key=up.unquote(u.username or q.get("privatekey", "")),
             wg_peer_public_key=q.get("publickey") or q.get("peer_public_key") or q.get("pk", ""),
             wg_preshared_key=q.get("presharedkey", ""), wg_address=addr,
             wg_reserved=reserved, wg_mtu=int(q.get("mtu", 0) or 0))
    awg = {AWG_KEYS[k.lower()]: _awg_value(AWG_KEYS[k.lower()], v) for k, v in q.items() if k.lower() in AWG_KEYS}
    if awg and not _awg_is_plain(awg):
        awg["version"] = awg_version(awg)
        n.type = "amneziawg"
        n.extra["awg"] = awg
    return n


def parse_socks_http(link: str) -> Node:
    u = up.urlsplit(link)
    scheme = u.scheme.lower()
    user = up.unquote(u.username or "")
    pw = up.unquote(u.password or "")
    if user and not pw and scheme.startswith("socks"):
        try:
            dec = b64decode_loose(user).decode()
            if ":" in dec:
                user, pw = dec.split(":", 1)
        except (ParseError, UnicodeDecodeError):
            pass
    n = Node(type="socks" if scheme.startswith("socks") else "http", server=u.hostname or "",
             port=u.port or (443 if scheme == "https" else 1080), uuid=user, password=pw, remark=_fragment(u))
    n.tls = scheme == "https"
    return n


def parse_anytls(link: str) -> Node:
    u = up.urlsplit(link)
    q = _q(u.query)
    host, port = _host_port(u.netloc.rsplit("@", 1)[-1])
    n = Node(type="anytls", server=host, port=port, password=up.unquote(u.username or ""), remark=_fragment(u))
    _apply_tls(n, q, default_tls=True)
    n.tls = True
    return n


SCHEMES = {
    "vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan, "ss": parse_ss,
    "hysteria2": parse_hysteria2, "hy2": parse_hysteria2, "tuic": parse_tuic,
    "wireguard": parse_wireguard, "wg": parse_wireguard,
    "socks": parse_socks_http, "socks5": parse_socks_http, "http": parse_socks_http,
    "https": parse_socks_http, "anytls": parse_anytls,
}

UNSUPPORTED = {"tg", "ssr", "hysteria", "naive+https", "naive+quic", "juicity", "mieru"}


def parse_link(link: str) -> Node:
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    fn = SCHEMES.get(scheme)
    if not fn:
        raise ParseError(f"unsupported scheme: {scheme}")
    n = fn(link)
    if not n.server or not n.port:
        raise ParseError("server/port missing")
    return n


# ---------------------------------------------------------------- containers
# AmneziaWG [Interface] keys -> mihomo amnezia-wg-option keys
AWG_KEYS = {
    "jc": "jc", "jmin": "jmin", "jmax": "jmax", "s1": "s1", "s2": "s2", "s3": "s3", "s4": "s4",
    "h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "i1": "i1", "i2": "i2", "i3": "i3", "i4": "i4", "i5": "i5",
    "j1": "j1", "j2": "j2", "j3": "j3", "itime": "itime",
    # 3.0
    "headerprotectionkey": "header-protection-key", "contentpaddingaddition": "content-padding-addition",
    "rekeyaftertime": "rekey-after-time", "rekeytimeout": "rekey-timeout", "rejectaftertime": "reject-after-time",
    "keepalivetimeout": "keepalive-timeout", "maxhandshakeattempts": "max-handshake-attempts",
    # 3.1
    "randomtrailers": "random-trailers", "disablecookies": "disable-cookies",
}
AWG_INT = {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime", "rekey-after-time", "rekey-timeout",
           "reject-after-time", "keepalive-timeout", "max-handshake-attempts"}
AWG_V3 = {"header-protection-key", "content-padding-addition", "rekey-after-time", "rekey-timeout",
          "reject-after-time", "keepalive-timeout", "max-handshake-attempts", "random-trailers", "disable-cookies"}


def awg_version(opts: dict) -> int:
    if any(k in opts for k in AWG_V3):
        return 3
    if any(k in opts for k in ("s3", "s4")) or any("-" in str(opts.get(h, "")) for h in ("h1", "h2", "h3", "h4")):
        return 2
    return 1


def _awg_value(key: str, v: str):
    if key in AWG_INT and re.fullmatch(r"-?\d+", v):
        return int(v)
    if key in ("random-trailers", "disable-cookies"):
        return _bool(v)
    return v


def _awg_is_plain(awg: dict) -> bool:
    """All obfuscation at WireGuard defaults: talk to it as plain WireGuard via sing-box."""
    for k, v in awg.items():
        if k in ("h1", "h2", "h3", "h4"):
            if str(v) not in (k[1],):
                return False
        elif k in ("version",):
            continue
        elif str(v) not in ("", "0", "False", "false"):
            return False
    return True


def parse_wireguard_conf(text: str, name: str = "WireGuard") -> Node:
    """WireGuard or AmneziaWG (1.0 / 1.5 / 2.0 / 3.0 / 3.1) .conf file."""
    sect, iface, peer = None, {}, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            sect = line.strip("[]").lower()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        if not k.lower().startswith(("i", "j")):      # I1..I5 / J1..J3 may legally contain '#'
            v = v.split("#", 1)[0].strip()
        (iface if sect == "interface" else peer)[k.lower()] = v
    if "privatekey" not in iface or "endpoint" not in peer:
        raise ParseError("not a WireGuard config")
    host, port = peer["endpoint"].rsplit(":", 1)
    awg = {AWG_KEYS[k]: _awg_value(AWG_KEYS[k], v) for k, v in iface.items() if k in AWG_KEYS and v != ""}
    if _awg_is_plain(awg):
        awg = {}
    n = Node(type="amneziawg" if awg else "wireguard", server=host.strip("[]"), port=int(port), remark=name,
             wg_private_key=iface["privatekey"], wg_peer_public_key=peer.get("publickey", ""),
             wg_preshared_key=peer.get("presharedkey", ""),
             wg_address=[a.strip() for a in iface.get("address", "").split(",") if a.strip()],
             wg_mtu=int(iface.get("mtu", 0) or 0))
    if awg:
        awg["version"] = awg_version(awg)
        n.extra["awg"] = awg
    if peer.get("persistentkeepalive", "").isdigit():
        n.extra["keepalive"] = int(peer["persistentkeepalive"])
    if iface.get("dns"):
        n.extra["dns"] = [d.strip() for d in iface["dns"].split(",") if d.strip()]
    n.extra["conf"] = text.strip()
    return n


def parse_openvpn(text: str, name: str = "OpenVPN", username: str = "", password: str = "") -> Node:
    remote = re.search(r"^[ \t]*remote[ \t]+(\S+)(?:[ \t]+(\d+))?(?:[ \t]+([\w-]+))?", text, re.M)
    if not remote:
        raise ParseError("в .ovpn нет строки remote")
    proto = re.search(r"^[ \t]*proto[ \t]+([\w-]+)", text, re.M)
    port = re.search(r"^[ \t]*port[ \t]+(\d+)", text, re.M)
    n = Node(type="openvpn", server=remote.group(1), remark=name, uuid=username, password=password,
             port=int(remote.group(2) or (port.group(1) if port else 1194)))
    n.transport = (remote.group(3) or (proto.group(1) if proto else "udp")).lower().replace("-client", "")
    n.extra["ovpn"] = text.strip()
    n.extra["needs_auth"] = bool(re.search(r"^\s*auth-user-pass\s*$", text, re.M))
    return n


def parse_ikev2_link(link: str) -> Node:
    """Own format: ikev2://user:pass@host[:500]?auth=eap|cert&strong=1#Name"""
    u = up.urlsplit(link)
    q = _q(u.query)
    n = Node(type="ikev2", server=u.hostname or "", port=u.port or 500, uuid=up.unquote(u.username or ""),
             password=up.unquote(u.password or ""), remark=_fragment(u))
    n.extra["auth"] = q.get("auth", "eap")
    n.extra["strong"] = _bool(q.get("strong", "1"))
    return n


SCHEMES["ikev2"] = parse_ikev2_link


def parse_amnezia_vpn(link: str) -> list[Node]:
    """AmneziaVPN 'vpn://' export: base64url(qCompress(json))."""
    import zlib
    raw = b64decode_loose(link[len("vpn://"):])
    try:
        data = json.loads(zlib.decompress(raw[4:]))
    except (zlib.error, ValueError):
        data = json.loads(raw)
    name = data.get("description") or data.get("name") or data.get("hostName") or "Amnezia"
    out: list[Node] = []

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                yield from walk(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from walk(v)
        elif isinstance(obj, str):
            s = obj.strip()
            if s.startswith("{"):
                try:
                    yield from walk(json.loads(s))
                except ValueError:
                    pass
            elif "[Interface]" in s or re.search(r"^\s*remote\s", s, re.M) or "://" in s[:20]:
                yield s

    for text in walk(data):
        try:
            if "[Interface]" in text:
                out.append(parse_wireguard_conf(text, name))
            elif re.search(r"^\s*remote\s", text, re.M):
                out.append(parse_openvpn(text, name))
            elif "://" in text[:20]:
                out.append(parse_link(text))
        except (ParseError, ValueError, KeyError):
            continue
    if not out:
        raise ParseError("в vpn:// не найдено поддерживаемой конфигурации")
    return out


def _clash_proxy(p: dict) -> Node | None:
    t = p.get("type", "")
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    reality = p.get("reality-opts") or {}
    common = dict(server=str(p.get("server", "")), port=int(p.get("port", 0) or 0), remark=str(p.get("name", "")))
    if t in ("vless", "vmess", "trojan"):
        q = {"type": p.get("network", "tcp"), "path": ws.get("path", ""),
             "host": (ws.get("headers") or {}).get("Host", ""),
             "serviceName": grpc.get("grpc-service-name", ""),
             "security": "reality" if reality else ("tls" if p.get("tls") or t == "trojan" else "none"),
             "sni": p.get("servername") or p.get("sni", ""), "alpn": ",".join(p.get("alpn", []) or []),
             "fp": p.get("client-fingerprint", ""), "allowInsecure": str(p.get("skip-cert-verify", False)),
             "pbk": reality.get("public-key", ""), "sid": reality.get("short-id", "")}
        n = Node(type=t, uuid=str(p.get("uuid", "")), password=str(p.get("password", "")),
                 flow=p.get("flow", ""), alter_id=int(p.get("alterId", 0) or 0),
                 security=p.get("cipher", "auto") if t == "vmess" else "auto", **common)
        _apply_transport(n, q)
        _apply_tls(n, q)
        return n
    if t == "ss":
        return Node(type="shadowsocks", method=p.get("cipher", ""), password=str(p.get("password", "")), **common)
    if t == "hysteria2":
        n = Node(type="hysteria2", password=str(p.get("password", "")), obfs=p.get("obfs", ""),
                 obfs_password=p.get("obfs-password", ""), tls=True, sni=p.get("sni", ""),
                 insecure=bool(p.get("skip-cert-verify")), alpn=p.get("alpn") or ["h3"], **common)
        return n
    if t == "tuic":
        return Node(type="tuic", uuid=str(p.get("uuid", "")), password=str(p.get("password", "")), tls=True,
                    sni=p.get("sni", ""), insecure=bool(p.get("skip-cert-verify")), alpn=p.get("alpn") or ["h3"],
                    congestion=p.get("congestion-controller", "bbr"),
                    udp_relay_mode=p.get("udp-relay-mode", "native"), **common)
    if t == "wireguard":
        ip = [x for x in (p.get("ip"), p.get("ipv6")) if x]
        awg = dict(p.get("amnezia-wg-option") or {})
        n = Node(type="amneziawg" if awg else "wireguard", wg_private_key=p.get("private-key", ""),
                 wg_peer_public_key=p.get("public-key", ""), wg_preshared_key=p.get("pre-shared-key", ""),
                 wg_address=[a if "/" in a else a + ("/128" if ":" in a else "/32") for a in ip],
                 wg_reserved=p.get("reserved") or [], wg_mtu=int(p.get("mtu", 0) or 0), **common)
        if awg:
            awg.setdefault("version", awg_version(awg))
            n.extra["awg"] = awg
        return n
    if t in ("socks5", "http"):
        return Node(type="socks" if t == "socks5" else "http", uuid=str(p.get("username", "")),
                    password=str(p.get("password", "")), tls=bool(p.get("tls")), **common)
    return None


def _singbox_outbound(o: dict) -> Node | None:
    t = o.get("type")
    if t not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "socks", "http", "anytls"):
        return None
    n = Node(type=t, server=o.get("server", ""), port=int(o.get("server_port", 0)), remark=o.get("tag", ""),
             uuid=o.get("uuid", "") or o.get("username", ""), password=o.get("password", ""),
             method=o.get("method", ""), flow=o.get("flow", ""), security=o.get("security", "auto"))
    tls = o.get("tls") or {}
    n.tls = bool(tls.get("enabled"))
    n.sni = tls.get("server_name", "")
    n.alpn = tls.get("alpn", []) or []
    n.insecure = bool(tls.get("insecure"))
    n.fingerprint = (tls.get("utls") or {}).get("fingerprint", "")
    r = tls.get("reality") or {}
    if r.get("enabled"):
        n.reality_pbk, n.reality_sid = r.get("public_key", ""), r.get("short_id", "")
    tr = o.get("transport") or {}
    n.transport = tr.get("type", "")
    n.path, n.service_name = tr.get("path", ""), tr.get("service_name", "")
    h = tr.get("host") or (tr.get("headers") or {}).get("Host", "")
    n.host = h[0] if isinstance(h, list) and h else (h or "")
    obfs = o.get("obfs") or {}
    n.obfs, n.obfs_password = obfs.get("type", ""), obfs.get("password", "")
    return n


def parse_subscription(body: str | bytes, group: str = "") -> tuple[list[Node], list[str]]:
    """Return (nodes, warnings)."""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    text = body.strip().lstrip("\ufeff")
    nodes: list[Node] = []
    warnings: list[str] = []

    if text.startswith("{"):
        try:
            data = json.loads(text)
            for o in data.get("outbounds", []) + data.get("endpoints", []):
                n = _singbox_outbound(o)
                if n:
                    nodes.append(n)
        except ValueError as e:
            warnings.append(f"JSON: {e}")
    elif "[Interface]" in text and "PrivateKey" in text:
        nodes.append(parse_wireguard_conf(text, group or "WireGuard"))
    elif re.search(r"^\s*remote\s+\S+", text, re.M) and re.search(r"^\s*(client|tls-client|pull)\s*$", text, re.M):
        nodes.append(parse_openvpn(text, group or "OpenVPN"))
    elif re.search(r"^\s*proxies\s*:", text, re.M):
        if yaml is None:
            raise ParseError("PyYAML не установлен — Clash-подписки недоступны")
        data = yaml.safe_load(text) or {}
        for p in data.get("proxies", []) or []:
            try:
                n = _clash_proxy(p)
                if n:
                    nodes.append(n)
                else:
                    warnings.append(f"Clash: тип {p.get('type')} не поддерживается")
            except (ValueError, TypeError) as e:
                warnings.append(f"Clash {p.get('name')}: {e}")
    else:
        if "://" not in text:
            try:
                text = b64decode_loose(text).decode("utf-8", "replace")
            except ParseError as e:
                raise ParseError("Неизвестный формат подписки") from e
        for line in _lines(text):
            scheme = line.split("://", 1)[0].lower()
            if scheme in UNSUPPORTED:
                warnings.append(f"{scheme}:// пропущен (не VPN-протокол или не поддерживается)")
                continue
            if scheme == "vpn":
                try:
                    nodes.extend(parse_amnezia_vpn(line))
                except (ParseError, ValueError) as e:
                    warnings.append(f"vpn://: {e}")
                continue
            try:
                nodes.append(parse_link(line))
            except (ParseError, ValueError, KeyError, UnicodeDecodeError) as e:
                warnings.append(f"{scheme}: {e}")

    seen: dict[str, int] = {}
    for n in nodes:
        n.group = group
        base = n.remark or f"{n.type}-{n.server}"
        seen[base] = seen.get(base, 0) + 1
        n.tag = base if seen[base] == 1 else f"{base} #{seen[base]}"
    return nodes, warnings


def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if "://" in line and not line.startswith("#"):
            yield line
