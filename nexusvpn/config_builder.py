"""Builds sing-box (and, for xhttp nodes, xray) configurations from settings + nodes."""
from __future__ import annotations

import ipaddress
import json
import re

from . import paths
from .models import Node
from .discord_voice import DISCORD_VOICE_CIDRS
from .presets import (DISCORD_DOMAINS, DISCORD_PROCESS_REGEX, TELEGRAM_CIDRS, enabled_presets, game_rules)

FAKEIP_V4, FAKEIP_V6 = "198.18.0.0/15", "fc00::/18"

XRAY_BASE_PORT = 10850
MIHOMO_BASE_PORT = 10900
CORE_PROCESSES = ["sing-box.exe", "xray.exe", "mihomo.exe", "openvpn.exe", "sing-box", "xray", "mihomo", "openvpn"]


def probe_ports(settings) -> tuple[int, int]:
    p = int(settings["mixed_port"])
    return p + 1, p + 2      # probe-direct, probe-proxy


# ------------------------------------------------------------------ outbounds
def _tls(n: Node, quic: bool = False) -> dict:
    t: dict = {"enabled": True, "server_name": n.sni or n.host or n.server}
    if n.insecure:
        t["insecure"] = True
    if n.alpn:
        # WebSocket/HTTPUpgrade cannot run over h2: panels often advertise "h2,http/1.1" anyway
        t["alpn"] = ["http/1.1"] if n.transport in ("ws", "httpupgrade") else n.alpn
    if n.fingerprint and not quic:
        t["utls"] = {"enabled": True, "fingerprint": n.fingerprint if n.fingerprint != "random" else "randomized"}
    if n.reality_pbk:
        t["reality"] = {"enabled": True, "public_key": n.reality_pbk, "short_id": n.reality_sid}
        t.pop("insecure", None)
        t.pop("alpn", None)
        t.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return t


def _transport(n: Node) -> dict | None:
    t = n.transport
    if not t:
        return None
    if t == "ws":
        d: dict = {"type": "ws", "path": n.path or "/"}
        if n.host:
            d["headers"] = {"Host": n.host}
        if n.early_data:
            d["max_early_data"] = n.early_data
            d["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return d
    if t == "grpc":
        return {"type": "grpc", "service_name": n.service_name or n.path}
    if t in ("http", "h2"):
        d = {"type": "http", "path": n.path or "/"}
        if n.host:
            d["host"] = [h.strip() for h in n.host.split(",")]
        return d
    if t == "httpupgrade":
        d = {"type": "httpupgrade", "path": n.path or "/"}
        if n.host:
            d["host"] = n.host
        return d
    if t == "quic":
        return {"type": "quic"}
    raise ValueError(f"транспорт {t} не поддерживается sing-box")


def _ss_plugin(spec: str) -> tuple[str, str]:
    parts = spec.split(";", 1)
    name = {"simple-obfs": "obfs-local"}.get(parts[0], parts[0])
    return name, parts[1] if len(parts) > 1 else ""


def assign_helpers(nodes: list[Node]) -> dict[str, int]:
    """Local SOCKS port of every node that is carried by xray or mihomo."""
    out, xi, mi = {}, 0, 0
    for n in nodes:
        if n.helper == "xray":
            out[n.tag] = XRAY_BASE_PORT + xi
            xi += 1
        elif n.helper == "mihomo":
            out[n.tag] = MIHOMO_BASE_PORT + mi
            mi += 1
    return out


def node_outbound(n: Node, helper_port: int | None = None, iface: str | None = None) -> tuple[str, dict]:
    """Return ("outbounds"|"endpoints", object)."""
    if n.helper in ("xray", "mihomo"):
        return "outbounds", {"type": "socks", "tag": n.tag, "server": "127.0.0.1",
                             "server_port": helper_port, "version": "5"}
    if n.is_system_tunnel:
        if not iface:
            raise ValueError(f"{n.type}: туннель не поднят")
        # OpenVPN / IKEv2 are real OS adapters: dial through them by binding to the interface
        return "outbounds", {"type": "direct", "tag": n.tag, "bind_interface": iface}
    base: dict = {"tag": n.tag, "server": n.server, "server_port": n.port}
    t = n.type
    if t == "vless":
        o = {"type": "vless", **base, "uuid": n.uuid, "packet_encoding": "xudp"}
        if n.flow:
            o["flow"] = n.flow
    elif t == "vmess":
        o = {"type": "vmess", **base, "uuid": n.uuid, "security": n.security or "auto",
             "alter_id": n.alter_id, "packet_encoding": "xudp"}
    elif t == "trojan":
        o = {"type": "trojan", **base, "password": n.password}
    elif t == "shadowsocks":
        o = {"type": "shadowsocks", **base, "method": n.method, "password": n.password}
        if n.extra.get("plugin"):
            o["plugin"], o["plugin_opts"] = _ss_plugin(n.extra["plugin"])
    elif t == "hysteria2":
        o = {"type": "hysteria2", **base, "password": n.password, "tls": _tls(n, quic=True)}
        if n.extra.get("server_ports"):
            o["server_ports"] = n.extra["server_ports"]
            o["hop_interval"] = "30s"
        if n.obfs:
            o["obfs"] = {"type": n.obfs, "password": n.obfs_password}
        if n.extra.get("up_mbps"):
            o["up_mbps"] = n.extra["up_mbps"]
        if n.extra.get("down_mbps"):
            o["down_mbps"] = n.extra["down_mbps"]
        return "outbounds", o
    elif t == "tuic":
        o = {"type": "tuic", **base, "uuid": n.uuid, "password": n.password,
             "congestion_control": n.congestion or "bbr", "udp_relay_mode": n.udp_relay_mode or "native",
             "zero_rtt_handshake": False, "heartbeat": "10s", "tls": _tls(n, quic=True)}
        return "outbounds", o
    elif t == "wireguard":
        peer = {"address": n.server, "port": n.port, "public_key": n.wg_peer_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive_interval": 25}
        if n.wg_preshared_key:
            peer["pre_shared_key"] = n.wg_preshared_key
        if n.wg_reserved:
            peer["reserved"] = n.wg_reserved
        return "endpoints", {"type": "wireguard", "tag": n.tag, "address": n.wg_address or ["10.0.0.2/32"],
                             "private_key": n.wg_private_key, "mtu": n.wg_mtu or 1408, "peers": [peer]}
    elif t == "socks":
        o = {"type": "socks", **base, "version": "5"}
        if n.uuid:
            o["username"], o["password"] = n.uuid, n.password
        return "outbounds", o
    elif t == "http":
        o = {"type": "http", **base}
        if n.uuid:
            o["username"], o["password"] = n.uuid, n.password
        if n.tls:
            o["tls"] = _tls(n)
        return "outbounds", o
    elif t == "anytls":
        o = {"type": "anytls", **base, "password": n.password, "tls": _tls(n)}
        return "outbounds", o
    else:
        raise ValueError(f"тип {t} не поддерживается")

    if n.tls:
        o["tls"] = _tls(n)
    tr = _transport(n)
    if tr:
        o["transport"] = tr
    return "outbounds", o


# ------------------------------------------------------------------ xray
def xray_outbound(n: Node) -> dict:
    stream: dict = {"network": "xhttp"}
    xs: dict = {"path": n.path or "/", "mode": n.xhttp_mode or "auto"}
    if n.host:
        xs["host"] = n.host
    if n.xhttp_extra:
        xs["extra"] = n.xhttp_extra
    stream["xhttpSettings"] = xs
    if n.reality_pbk:
        stream["security"] = "reality"
        stream["realitySettings"] = {"serverName": n.sni, "fingerprint": n.fingerprint or "chrome",
                                     "publicKey": n.reality_pbk, "shortId": n.reality_sid,
                                     "spiderX": n.extra.get("spx", "")}
    elif n.tls:
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": n.sni or n.host or n.server, "allowInsecure": n.insecure,
                                 "fingerprint": n.fingerprint or "chrome"}
        if n.alpn:
            stream["tlsSettings"]["alpn"] = n.alpn
    user: dict = {"id": n.uuid, "encryption": "none"}
    if n.type == "vless":
        if n.flow:
            user["flow"] = n.flow
        proto = "vless"
    elif n.type == "vmess":
        user = {"id": n.uuid, "security": n.security or "auto"}
        proto = "vmess"
    else:
        raise ValueError(f"xhttp для {n.type} не поддерживается")
    return {"protocol": proto, "tag": "out",
            "settings": {"vnext": [{"address": n.server, "port": n.port, "users": [user]}]},
            "streamSettings": stream}


def build_xray(nodes: list[Node], log_level: str = "warning") -> dict | None:
    xn = [n for n in nodes if n.needs_xray]
    if not xn:
        return None
    ports = assign_helpers(nodes)
    inbounds, outbounds, rules = [], [], []
    for i, n in enumerate(xn):
        port = ports[n.tag]
        inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": port, "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}})
        ob = xray_outbound(n)
        ob["tag"] = f"out{i}"
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"})
    lvl = {"trace": "debug", "debug": "debug", "info": "info", "warn": "warning", "error": "error"}.get(log_level, "warning")
    return {"log": {"loglevel": lvl}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


# ------------------------------------------------------------------ mihomo (AmneziaWG)
def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return json.dumps(str(v), ensure_ascii=False)   # JSON strings are valid YAML


def build_mihomo(nodes: list[Node], log_level: str = "warning") -> str | None:
    """mihomo carries AmneziaWG 1.0-3.1: one SOCKS listener per AWG node."""
    an = [n for n in nodes if n.helper == "mihomo"]
    if not an:
        return None
    ports = assign_helpers(nodes)
    lvl = {"trace": "debug", "debug": "debug", "info": "info", "warn": "warning", "error": "error"}.get(
        log_level, "warning")
    y = ["mode: rule", f"log-level: {lvl}", "ipv6: false", "allow-lan: false", "find-process-mode: off",
         "unified-delay: true", "geodata-mode: false", "geo-auto-update: false", "profile:",
         "  store-selected: false", "  store-fake-ip: false", "proxies:"]
    for i, n in enumerate(an):
        ip4 = [a.split("/")[0] for a in n.wg_address if ":" not in a]
        ip6 = [a.split("/")[0] for a in n.wg_address if ":" in a]
        y += [f"  - name: awg{i}", "    type: wireguard", f"    server: {_yaml_scalar(n.server)}",
              f"    port: {n.port}", f"    private-key: {_yaml_scalar(n.wg_private_key)}",
              f"    public-key: {_yaml_scalar(n.wg_peer_public_key)}", "    udp: true",
              f"    mtu: {n.wg_mtu or 1280}", "    allowed-ips: ['0.0.0.0/0', '::/0']",
              f"    persistent-keepalive: {int(n.extra.get('keepalive', 25))}",
              # resolve through the tunnel: the ISP resolver may return poisoned answers
              "    remote-dns-resolve: true",
              f"    dns: [{', '.join(_yaml_scalar(d) for d in (n.extra.get('dns') or ['1.1.1.1', '8.8.8.8']))}]"]
        if ip4:
            y.append(f"    ip: {_yaml_scalar(ip4[0])}")
        if ip6:
            y.append(f"    ipv6: {_yaml_scalar(ip6[0])}")
        if n.wg_preshared_key:
            y.append(f"    pre-shared-key: {_yaml_scalar(n.wg_preshared_key)}")
        if n.wg_reserved:
            y.append(f"    reserved: {n.wg_reserved}")
        awg = dict(n.extra.get("awg") or {})
        if awg:
            y.append("    amnezia-wg-option:")
            for k, v in awg.items():
                y.append(f"      {k}: {_yaml_scalar(v)}")
    y.append("listeners:")
    for i, n in enumerate(an):
        y += [f"  - name: in{i}", "    type: socks", f"    port: {ports[n.tag]}", "    listen: 127.0.0.1",
              "    udp: true", f"    proxy: awg{i}"]
    y += ["rules:", "  - MATCH,DIRECT"]
    return "\n".join(y) + "\n"


# ------------------------------------------------------------------ main builder
def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip("[]"))
        return True
    except ValueError:
        return False


def _cidr(ip: str) -> str:
    return ip + ("/128" if ":" in ip else "/32")


def _rs_local(tag: str, path, fmt: str = "source") -> dict:
    return {"type": "local", "tag": tag, "format": fmt, "path": str(path)}


def ensure_rule_files() -> None:
    for p in (paths.LEARNED_PROXY_RS, paths.LEARNED_PROXY_IP_RS, paths.LEARNED_DIRECT_RS,
              paths.USER_PROXY_RS, paths.USER_DIRECT_RS, paths.USER_PROXY_IP_RS, paths.USER_DIRECT_IP_RS):
        if not p.exists():
            p.write_text(json.dumps({"version": 3, "rules": [{"domain": ["placeholder.invalid"]}]}), "utf-8")


def tun_scope(s, mode: str, tun_allowed: bool = True) -> str:
    """all     — every destination goes through sing-box
    include — only what may need the VPN enters the TUN; everything else never touches the program
    voice   — «Системный прокси»: a small TUN only for Discord/Telegram so voice and calls work too
    none    — no TUN"""
    capture = s["capture_mode"]
    if capture == "both" or (capture == "tun" and (mode == "global" or s["direct_bypass"] != "full")):
        return "all"
    if capture == "tun":
        return "include"
    voice = s["proxy_voice_tun"] and tun_allowed and mode != "direct" and (s["preset_discord"] or s["preset_telegram"])
    return "voice" if voice else "none"


FAKEIP_TTL = 5   # short: once smart routing files a site as direct, the next lookup gets the real address


def _rule_file_values(path, key: str) -> list[str]:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return []
    return [c for r in data.get("rules", []) for c in r.get(key, [])]


def _rule_file_cidrs(path) -> list[str]:
    return _rule_file_values(path, "ip_cidr")


def tun_routes(s, scope: str, use_presets: bool) -> list[str]:
    """Destinations that enter the TUN when it is not the default route. Domains that need the VPN
    resolve to FakeIP, so the FakeIP range carries them; raw-IP services are listed explicitly."""
    discord = use_presets and s["preset_discord"]
    telegram = use_presets and s["preset_telegram"]
    out = [] if scope == "voice" else [FAKEIP_V4] + ([FAKEIP_V6] if s["ipv6_mode"] != "off" else [])
    if telegram:
        out += TELEGRAM_CIDRS
    if discord:
        out += DISCORD_VOICE_CIDRS
    if scope == "include":
        out += _rule_file_cidrs(paths.USER_PROXY_IP_RS) + _rule_file_cidrs(paths.LEARNED_PROXY_IP_RS)
        # the router's / chosen DNS servers: queries to them are answered by sing-box (FakeIP)
        for value in (s["dns_local"], s["dns_local_alt"]):
            if _is_ip((value or "").strip()):
                out.append(_cidr(value.strip()))
    seen: set[str] = set()
    return [c for c in out if not (c in seen or seen.add(c))]


def build_singbox(settings, nodes: list[Node], log_level: str | None = None,
                  ifaces: dict[str, str] | None = None, exclude_ips: list[str] | None = None,
                  tun_allowed: bool = True) -> dict:
    """ifaces: tag -> OS adapter of a connected OpenVPN/IKEv2 tunnel; exclude_ips: resolved server IPs."""
    s = settings
    ifaces = ifaces or {}
    nodes = [n for n in nodes if n.enabled]
    if not nodes:
        raise ValueError("Нет ни одного включённого сервера")
    ensure_rule_files()
    mode = s["routing_mode"]
    if mode == "rules":
        mode = "custom"
    scope = tun_scope(s, mode, tun_allowed)
    p_direct, p_proxy = probe_ports(s)
    helpers = assign_helpers(nodes)

    # ---- nodes ----
    outbounds: list[dict] = []
    endpoints: list[dict] = []
    tags: list[str] = []
    udp_tags: list[str] = []
    for n in nodes:
        try:
            kind, ob = node_outbound(n, helpers.get(n.tag), ifaces.get(n.tag))
        except ValueError:
            continue
        (endpoints if kind == "endpoints" else outbounds).append(ob)
        tags.append(n.tag)
        if n.supports_udp:
            udp_tags.append(n.tag)
    if not tags:
        raise ValueError("Ни один сервер не готов к работе (проверьте журнал)")

    hc_url = s["health_check_url"]
    interval = f"{int(s['health_check_interval'])}s"
    groups = [{"type": "urltest", "tag": "auto", "outbounds": tags, "url": hc_url, "interval": interval,
               "tolerance": 80, "idle_timeout": "30m", "interrupt_exist_connections": False}]
    active = s["active_node"] if s["active_node"] in tags else "auto"
    groups.append({"type": "selector", "tag": "proxy", "outbounds": ["auto", *tags], "default": active,
                   "interrupt_exist_connections": True})
    use_presets = mode in ("smart", "global") or (mode == "custom" and s["custom_use_presets"])
    if scope == "voice" and not tun_routes(s, scope, use_presets):
        scope = "none"   # an empty route_address would make the TUN the default route
    discord_on = bool(s["preset_discord"]) and use_presets
    discord_out = "proxy"
    if discord_on and s["discord_isolate"] and udp_tags:
        groups.append({"type": "urltest", "tag": "auto-udp", "outbounds": udp_tags, "url": hc_url,
                       "interval": interval, "tolerance": 80, "idle_timeout": "30m",
                       # never cut a running voice call because another node got 5 ms faster
                       "interrupt_exist_connections": False})
        groups.append({"type": "selector", "tag": "discord", "outbounds": ["auto-udp", "proxy", *udp_tags],
                       "default": "auto-udp", "interrupt_exist_connections": False})
        discord_out = "discord"
    outbounds = outbounds + groups + [{"type": "direct", "tag": "direct"}]

    # ---- rule sets ----
    rule_sets = [_rs_local("user-proxy", paths.USER_PROXY_RS), _rs_local("user-direct", paths.USER_DIRECT_RS),
                 _rs_local("user-proxy-ip", paths.USER_PROXY_IP_RS),
                 _rs_local("user-direct-ip", paths.USER_DIRECT_IP_RS),
                 _rs_local("learned-proxy", paths.LEARNED_PROXY_RS),
                 _rs_local("learned-proxy-ip", paths.LEARNED_PROXY_IP_RS),
                 _rs_local("learned-direct", paths.LEARNED_DIRECT_RS)]
    preset_proxy, preset_direct, preset_discord = [], [], []
    if use_presets:
        for tag, _url, action in enabled_presets(s):
            f = paths.RULES_DIR / f"{tag}.srs"
            if not f.exists():
                continue
            rule_sets.append(_rs_local(tag, f, "binary"))
            {"proxy": preset_proxy, "direct": preset_direct, "discord": preset_discord}[action].append(tag)

    # ---- route rules ----
    server_ips = sorted({n.server for n in nodes if _is_ip(n.server)} | set(exclude_ips or []))
    rules: list[dict] = [
        {"action": "sniff", "timeout": "300ms"},
        {"protocol": "dns", "action": "hijack-dns"},
        {"inbound": ["probe-direct"], "outbound": "direct"},
        {"inbound": ["probe-proxy"], "outbound": "proxy"},
        # helper cores dial the real servers themselves; never loop them back into the tunnel
        {"process_name": CORE_PROCESSES, "outbound": "direct"},
    ]
    if server_ips:
        rules.append({"ip_cidr": [_cidr(ip) for ip in server_ips], "outbound": "direct"})
    if s["bypass_lan"]:
        rules.append({"ip_is_private": True, "outbound": "direct"})
    if s["ipv6_mode"] == "off":
        rules.append({"ip_version": 6, "network": "udp", "action": "reject"})
    if s["process_exclusions"]:
        rules.append({"process_name": s["process_exclusions"], "outbound": "direct"})
    if s["process_force_vpn"]:
        rules.append({"process_name": s["process_force_vpn"], "outbound": "proxy"})
    rules.append({"rule_set": ["user-direct", "user-direct-ip"], "outbound": "direct"})
    game_direct, game_proxy = game_rules(s)
    # before presets and learned rules: a learned "whole program -> VPN" must never catch a game
    if game_direct:
        rules.append({"process_path_regex": game_direct, "outbound": "direct"})
    if game_proxy:
        rules.append({"process_path_regex": game_proxy, "outbound": "proxy"})

    def discord_rules():
        if discord_on:
            rules.append({"process_path_regex": [DISCORD_PROCESS_REGEX], "outbound": discord_out})
            rules.append({"domain_suffix": DISCORD_DOMAINS, "outbound": discord_out})
            if preset_discord:
                rules.append({"rule_set": preset_discord, "outbound": discord_out})

    proxy_sets: list[str] = ["user-proxy"]
    if mode == "global":
        final = "proxy"
        discord_rules()
    elif mode == "direct":
        final = "direct"
    else:  # smart / custom
        final = "direct"
        rules.append({"rule_set": ["user-proxy", "user-proxy-ip"], "outbound": "proxy"})
        discord_rules()
        if use_presets:
            if s["preset_telegram"]:
                rules.append({"ip_cidr": TELEGRAM_CIDRS, "outbound": "proxy"})
            site_direct = [t for t in preset_direct if t != "geoip-ru"]
            if site_direct:
                rules.append({"rule_set": site_direct, "outbound": "direct"})
            if preset_proxy:
                rules.append({"rule_set": preset_proxy, "outbound": "proxy"})
        if mode == "smart":
            rules.append({"rule_set": ["learned-proxy", "learned-proxy-ip"], "outbound": "proxy"})
            rules.append({"rule_set": ["learned-direct"], "outbound": "direct"})
        if "geoip-ru" in preset_direct:
            rules.append({"rule_set": ["geoip-ru"], "outbound": "direct"})
        # IP-only sets are not allowed in DNS rules since sing-box 1.14
        proxy_sets += [t for t in preset_proxy if not t.endswith("-ip")]
        if mode == "smart":
            proxy_sets.append("learned-proxy")
        if s["block_quic_direct"]:
            # dead QUIC = 10-30 s stalls; reject so browsers instantly fall back to TCP we can learn from
            rules.append({"network": "udp", "port": 443, "action": "reject"})

    # ---- dns ----
    dns_servers = [
        _plain_dns("local", s["dns_local"]),
        _plain_dns("local-alt", s["dns_local_alt"]),
        _doh("remote", s["dns_remote"], "proxy"),
        {"tag": "bootstrap", "type": "udp", "server": "1.1.1.1"},
    ]
    dns_rules: list[dict] = []
    if mode == "global":
        dns_final = "remote"
        dns_rules.append({"rule_set": ["user-direct"], "server": "local"})
    elif mode == "direct":
        dns_final = "local"
    else:
        dns_final = "local"
        fakeip = s["dns_fakeip"] or scope == "include"
        addr = ["A", "AAAA"]
        if fakeip:
            dns_servers.append({"tag": "fakeip", "type": "fakeip", "inet4_range": FAKEIP_V4,
                                "inet6_range": FAKEIP_V6})
            # the user's direct list always wins and gets real addresses -> bypasses the TUN
            dns_rules.append({"rule_set": ["user-direct"], "server": "local"})
            dns_rules.append({"rule_set": proxy_sets, "query_type": addr, "action": "route", "server": "fakeip",
                              "rewrite_ttl": FAKEIP_TTL})
            if discord_on:
                dns_rules.append({"domain_suffix": DISCORD_DOMAINS, "query_type": addr, "action": "route",
                                  "server": "fakeip", "rewrite_ttl": FAKEIP_TTL})
        dns_rules.append({"rule_set": proxy_sets, "server": "remote"})
        if discord_on:
            dns_rules.append({"domain_suffix": DISCORD_DOMAINS, "server": "remote"})
        if scope == "include":
            known_direct = [t for t in preset_direct if t != "geoip-ru"] + (["learned-direct"] if mode == "smart" else [])
            if known_direct:
                dns_rules.append({"rule_set": known_direct, "server": "local"})
            # still unknown: smart routing must see it to learn; a program the user sends via VPN must be
            # caught even when it uses ordinary domains
            vpn_programs = bool(game_proxy) or bool(_rule_file_values(paths.USER_PROXY_RS, "process_name"))
            if mode == "smart" or vpn_programs:
                dns_rules.append({"query_type": addr, "action": "route", "server": "fakeip",
                                  "rewrite_ttl": FAKEIP_TTL})
    dns = {"servers": dns_servers, "rules": dns_rules, "final": dns_final,
           "strategy": s["dns_strategy"] if s["ipv6_mode"] != "off" else "ipv4_only",
           "cache_capacity": 8192}

    # ---- inbounds ----
    inbounds: list[dict] = []
    if scope != "none":
        tun = {"type": "tun", "tag": "tun-in", "interface_name": paths.APP_SHORT,
               "address": [s["tun_ipv4"]] + (["fdfe:dcba:9876::1/126"] if s["ipv6_mode"] != "off" else []),
               "mtu": int(s["tun_mtu"]), "auto_route": True, "strict_route": bool(s["strict_route"]),
               "stack": s["tun_stack"], "endpoint_independent_nat": bool(s["endpoint_independent_nat"]),
               "udp_timeout": s["udp_timeout"]}
        if server_ips:
            # VPN servers (incl. kernel-level IKEv2/OpenVPN-DCO traffic) must never enter our own TUN
            tun["route_exclude_address"] = [_cidr(ip) for ip in server_ips]
        if scope in ("include", "voice"):
            tun["route_address"] = tun_routes(s, scope, use_presets)
        if scope == "voice":
            # the browser uses the proxy; this TUN must not take over the system DNS
            tun["strict_route"] = False
        inbounds.append(tun)
    inbounds.append({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": int(s["mixed_port"])})
    inbounds.append({"type": "mixed", "tag": "probe-direct", "listen": "127.0.0.1", "listen_port": p_direct})
    inbounds.append({"type": "mixed", "tag": "probe-proxy", "listen": "127.0.0.1", "listen_port": p_proxy})

    cfg = {
        "log": {"level": log_level or s["log_level"], "timestamp": True},
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "rule_set": rule_sets, "final": final,
                  "auto_detect_interface": bool(s["auto_detect_interface"]),
                  "find_process": True, "default_domain_resolver": "local"},
        "experimental": {
            "cache_file": {"enabled": True, "path": str(paths.RUN_DIR / "cache.db"),
                           "store_fakeip": True},
            "clash_api": {"external_controller": f"127.0.0.1:{int(s['clash_api_port'])}",
                          "secret": s["clash_secret"], "default_mode": "rule"},
        },
    }
    if endpoints:
        cfg["endpoints"] = endpoints
    return cfg


def _plain_dns(tag: str, value: str) -> dict:
    """'dhcp' / 'auto' = the DNS the router hands out (what Windows uses without VPN)."""
    v = (value or "").strip().lower()
    if v in ("", "dhcp", "auto", "router"):
        return {"tag": tag, "type": "dhcp"}
    if "://" in v:
        return _doh_direct(tag, value)
    return {"tag": tag, "type": "udp", "server": value.strip()}


def _doh_direct(tag: str, url: str) -> dict:
    d = _doh(tag, url, "direct")
    d.pop("detour", None)
    return d


def _doh(tag: str, url: str, detour: str) -> dict:
    m = re.match(r"^(https|tls|quic|h3|udp|tcp)://([^/:]+)(?::(\d+))?(/.*)?$", url.strip())
    if not m:
        return {"tag": tag, "type": "udp", "server": url.strip(), "detour": detour}
    scheme, host, port, path = m.groups()
    d: dict = {"tag": tag, "type": scheme, "server": host, "detour": detour}
    if port:
        d["server_port"] = int(port)
    if scheme in ("https", "h3") and path and path != "/dns-query":
        d["path"] = path
    if not _is_ip(host):
        d["domain_resolver"] = "bootstrap"
    return d


def write_configs(settings, nodes: list[Node], ifaces: dict[str, str] | None = None,
                  exclude_ips: list[str] | None = None, tun_allowed: bool = True) -> tuple[dict, dict | None, str | None]:
    paths.ensure_dirs()
    enabled = [n for n in nodes if n.enabled]
    sb = build_singbox(settings, nodes, ifaces=ifaces, exclude_ips=exclude_ips, tun_allowed=tun_allowed)
    xr = build_xray(enabled, settings["log_level"])
    mh = build_mihomo(enabled, settings["log_level"])
    paths.SINGBOX_CONFIG.write_text(json.dumps(sb, ensure_ascii=False, indent=2), "utf-8")
    for path, body in ((paths.XRAY_CONFIG, json.dumps(xr, ensure_ascii=False, indent=2) if xr else None),
                       (paths.MIHOMO_CONFIG, mh)):
        if body:
            path.write_text(body, "utf-8")
        elif path.exists():
            path.unlink()
    return sb, xr, mh
