import base64
import json
import shutil
import subprocess

import pytest

from nexusvpn import config_builder as cb
from nexusvpn.learner import base_domain
from nexusvpn.parsers import parse_link, parse_subscription, parse_wireguard_conf
from nexusvpn.settings import Settings

UUID = "00000000-1111-4222-8333-444444444444"
PBK = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
WG_PRIV = "YNXtAzepDqRv9H52osJVDQnznT5AL11eMRMnBTkHeEo="
WG_PUB = "JQkrPrE8fW7Fb+V7ZpRHoIHiIT1xRuTeRG4vyt36lRY="
VMESS = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "vm", "add": "1.2.3.4", "port": 9443, "id": UUID, "net": "ws", "path": "/vm",
    "tls": "tls", "sni": "1.2.3.4", "alpn": "h2,http/1.1", "scy": "auto"}).encode()).decode()
SS_KEY = base64.urlsafe_b64encode(b"2022-blake3-aes-256-gcm:" + base64.b64encode(b"k" * 32)).decode()

LINKS = [
    f"vless://{UUID}@1.2.3.4:442?type=tcp&security=reality&pbk={PBK}&sid=ab&sni=intel.com&fp=firefox"
    f"&flow=xtls-rprx-vision#reality",
    f"vless://{UUID}@1.2.3.4:443?type=xhttp&security=reality&pbk={PBK}&sid=ab&sni=www.cloudflare.com"
    f"&path=%2Fx&mode=auto&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#xhttp",
    f"vless://{UUID}@1.2.3.4:2053?type=grpc&security=reality&pbk={PBK}&sid=ab&sni=a.com&serviceName=g#grpc",
    f"vless://{UUID}@1.2.3.4:2083?type=ws&security=tls&sni=1.2.3.4&alpn=h2%2Chttp%2F1.1&path=%2Fws#ws",
    "hysteria2://pass@1.2.3.4:8443?sni=1.2.3.4&obfs=salamander&obfs-password=x#hy2",
    f"trojan://pw@1.2.3.4:2087?security=reality&pbk={PBK}&sid=ab&sni=intel.com&type=tcp#trojan",
    VMESS,
    f"ss://{SS_KEY}@1.2.3.4:10443#ss",
    f"wireguard://{WG_PRIV}@1.2.3.4:51820?address=10.0.0.2%2F32&publickey={WG_PUB}&mtu=1420#wg",
    "tuic://" + UUID + ":pw@1.2.3.4:443?sni=a.com&congestion_control=bbr#tuic",
    "socks://dXNlcjpwYXNz@1.2.3.4:1080#socks",
    "tg://proxy?server=1.2.3.4&port=1&secret=ee",
]


def test_all_links_parse():
    body = base64.b64encode("\n".join(LINKS).encode()).decode()
    nodes, warns = parse_subscription(body, "t")
    assert len(nodes) == 11
    assert len(warns) == 1 and "tg" in warns[0]
    by = {n.tag: n for n in nodes}
    assert by["reality"].reality_pbk == PBK and by["reality"].flow == "xtls-rprx-vision"
    assert by["xhttp"].needs_xray and by["xhttp"].xhttp_extra["xPaddingBytes"] == "100-1000"
    assert by["ws"].insecure, "IP as SNI means self-signed panel cert"
    assert by["ss"].method == "2022-blake3-aes-256-gcm"
    assert by["wg"].wg_address == ["10.0.0.2/32"]
    assert by["socks"].uuid == "user" and by["socks"].password == "pass"


def test_wireguard_conf():
    n = parse_wireguard_conf(f"[Interface]\nPrivateKey = {WG_PRIV}\nAddress = 10.8.0.2/32\n"
                             f"[Peer]\nPublicKey = {WG_PUB}\nEndpoint = 5.6.7.8:51820\n")
    assert n.server == "5.6.7.8" and n.port == 51820


def test_clash_yaml():
    y = f"""proxies:
  - {{name: a, type: vless, server: 1.2.3.4, port: 443, uuid: {UUID}, network: ws, tls: true,
      ws-opts: {{path: /p, headers: {{Host: h.com}}}}}}
  - {{name: b, type: hysteria2, server: 1.2.3.4, port: 443, password: x}}
"""
    nodes, _ = parse_subscription(y)
    assert [n.type for n in nodes] == ["vless", "hysteria2"] and nodes[0].host == "h.com"


def test_ws_alpn_forced_http11():
    n = parse_link(LINKS[3])
    _, ob = cb.node_outbound(n)
    assert ob["tls"]["alpn"] == ["http/1.1"]


def test_base_domain():
    assert base_domain("rr3---sn.googlevideo.com") == "googlevideo.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("abc.cloudfront.net") == "abc.cloudfront.net"


@pytest.mark.skipif(not shutil.which("sing-box"), reason="sing-box binary not on PATH")
@pytest.mark.parametrize("mode", ["smart", "global", "custom"])
@pytest.mark.parametrize("fakeip", [False, True])
def test_config_passes_singbox_check(tmp_path, mode, fakeip):
    s = Settings(tmp_path / "s.json")
    s.update(routing_mode=mode, dns_fakeip=fakeip, clash_secret="x")
    nodes, _ = parse_subscription("\n".join(LINKS))
    cb.write_configs(s, nodes)
    from nexusvpn import paths
    r = subprocess.run(["sing-box", "check", "-c", str(paths.SINGBOX_CONFIG)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


AWG3 = f"""[Interface]
PrivateKey = {WG_PRIV}
Address = 10.9.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 68
S3 = 20
S4 = 16
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
I1 = <b 0xc70000000108><r 16><t>
HeaderProtectionKey = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
ContentPaddingAddition = 0-32
[Peer]
PublicKey = {WG_PUB}
Endpoint = 1.2.3.4:51820
"""


def test_amneziawg_v3():
    n = parse_wireguard_conf(AWG3, "awg")
    assert n.type == "amneziawg" and n.helper == "mihomo"
    a = n.extra["awg"]
    assert a["version"] == 3 and a["header-protection-key"].endswith("=") and a["i1"].startswith("<b")


def test_plain_wireguard_not_awg():
    conf = f"[Interface]\nPrivateKey = {WG_PRIV}\nAddress = 10.0.0.2/32\nJc = 0\nH1 = 1\nH2 = 2\n" \
           f"[Peer]\nPublicKey = {WG_PUB}\nEndpoint = 1.2.3.4:51820\n"
    assert parse_wireguard_conf(conf).type == "wireguard"


def test_openvpn_and_ikev2():
    from nexusvpn.parsers import parse_openvpn
    o = parse_openvpn("client\nproto tcp-client\nremote vpn.example.com 443\nauth-user-pass\n")
    assert (o.type, o.server, o.port, o.transport, o.extra["needs_auth"]) == \
        ("openvpn", "vpn.example.com", 443, "tcp", True)
    k = parse_link("ikev2://u:p@vpn.example.com#IKE")
    assert k.type == "ikev2" and k.uuid == "u" and k.is_system_tunnel


def test_amnezia_vpn_link():
    import struct
    import zlib
    payload = json.dumps({"containers": [{"awg": {"last_config": json.dumps({"config": AWG3})}}],
                          "description": "Mine"}).encode()
    link = "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(payload)) + zlib.compress(payload)).decode()
    nodes, _ = parse_subscription(link)
    assert [(n.type, n.remark) for n in nodes] == [("amneziawg", "Mine")]


def test_link_roundtrip():
    from nexusvpn.links import from_text, to_text
    nodes, _ = parse_subscription("\n".join(LINKS))
    nodes.append(parse_wireguard_conf(AWG3, "awg"))
    for n in nodes:
        m = from_text(to_text(n))
        for f in ("type", "server", "port", "uuid", "password", "transport", "path", "reality_pbk", "sni"):
            assert getattr(n, f) == getattr(m, f), (n.tag, f)


def test_batch_rules():
    from nexusvpn.rules_text import parse_text
    e, err = parse_text("youtube.com, *.discord.gg https://www.instagram.com/p/1\n1.2.3.4 10.0.0.0/8\n"
                        "full:api.openai.com keyword:tiktok\nC:\\Program Files\\X\\game.exe\n# c\nbad!!")
    assert ("domain", "discord.gg") in e and ("domain", "instagram.com") in e
    assert ("ip", "1.2.3.4/32") in e and ("ip", "10.0.0.0/8") in e
    assert ("full", "api.openai.com") in e and ("keyword", "tiktok") in e and ("process", "game.exe") in e
    assert len(err) == 1


@pytest.mark.skipif(not shutil.which("mihomo"), reason="mihomo binary not on PATH")
def test_mihomo_config_valid(tmp_path):
    from nexusvpn.config_builder import build_mihomo
    n = parse_wireguard_conf(AWG3, "awg")
    n.tag = "awg"
    f = tmp_path / "m.yaml"
    f.write_text(build_mihomo([n]))
    r = subprocess.run(["mihomo", "-t", "-d", str(tmp_path), "-f", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


GAME_PATHS = {
    r"C:\Program Files (x86)\Call of Duty\_retail_\cod.exe": True,
    r"D:\SteamLibrary\steamapps\common\Call of Duty HQ\cod.exe": True,
    r"C:\Program Files (x86)\Battle.net\Battle.net.exe": True,
    r"C:\Program Files (x86)\Steam\steam.exe": False,
    r"C:\Users\u\AppData\Local\Discord\app-1.0.9\Discord.exe": False,
    r"C:\Program Files\Google\Chrome\Application\chrome.exe": False,
}


def _games_settings(tmp_path, **games):
    s = Settings(tmp_path / "s.json")
    s.update(games=games or {"cod": "direct", "battlenet": "direct"})
    return s


def test_game_presets_match_paths(tmp_path):
    import re
    from nexusvpn.presets import game_rules
    direct, proxy = game_rules(_games_settings(tmp_path))
    assert not proxy
    for path, is_game in GAME_PATHS.items():
        assert any(re.search(r, path) for r in direct) == is_game, path


def test_games_off_by_default(tmp_path):
    from nexusvpn.presets import game_rules
    assert game_rules(Settings(tmp_path / "s.json")) == ([], [])


def test_old_games_switch_migrates(tmp_path):
    import json
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"games_direct": True, "game_folders": ["Call of Duty"]}), "utf-8")
    s = Settings(p)
    assert s["games"] == {"cod": "direct", "battlenet": "direct"} and "game_folders" not in s.data


def test_game_rules_before_learned_rules(tmp_path):
    s = _games_settings(tmp_path, cod="direct", steam="proxy")
    s.update(routing_mode="smart")
    rules = cb.build_singbox(s, parse_subscription("\n".join(LINKS))[0])["route"]["rules"]
    game = next(i for i, r in enumerate(rules) if "process_path_regex" in r and r["outbound"] == "direct")
    vpn_game = next(i for i, r in enumerate(rules) if "process_path_regex" in r and r["outbound"] == "proxy"
                    and "steamapps" in r["process_path_regex"][0])
    learned = next(i for i, r in enumerate(rules) if "learned-proxy" in r.get("rule_set", []))
    assert game < learned and vpn_game < learned


def test_learner_ignores_games(tmp_path):
    from nexusvpn.learner import Learner
    s = _games_settings(tmp_path)
    s.update(learn_min_bytes=500, learn_probe_interval=5)
    lr = Learner.__new__(Learner)
    lr.s, lr._tracks, suspects = s, {}, []
    lr._suspect = lambda t: suspects.append(t.process)
    lr._remember_direct = lambda h: None

    def conns(up):
        return [{"id": str(i), "chains": ["direct"], "upload": up, "download": 0,
                 "metadata": {"processPath": p, "destinationIP": f"4.207.247.{i}", "destinationPort": 443,
                              "network": "tcp", "host": ""}}
                for i, p in enumerate(GAME_PATHS)]
    lr._scan(conns(0))
    for t in lr._tracks.values():
        t.first -= 60
    lr._scan(conns(800))
    assert "cod.exe" not in suspects and "Battle.net.exe" not in suspects
    assert "steam.exe" in suspects


def _tun(cfg):
    return next(i for i in cfg["inbounds"] if i["type"] == "tun")


def test_full_bypass_only_vpn_addresses_enter_tun(tmp_path):
    import ipaddress
    s = Settings(tmp_path / "s.json")
    s.update(capture_mode="tun", routing_mode="smart", direct_bypass="full")
    cfg = cb.build_singbox(s, parse_subscription("\n".join(LINKS))[0])
    nets = [ipaddress.ip_network(c) for c in _tun(cfg)["route_address"]]
    def inside(ip):
        return any(ipaddress.ip_address(ip) in n for n in nets)
    assert inside("198.18.0.5")                      # FakeIP: domains that need the VPN
    assert inside("149.154.167.51")                  # Telegram
    assert inside("104.29.157.153")                  # Discord voice (Cloudflare)
    assert not inside("212.102.63.139")              # Call of Duty match server: never touches the program
    assert not inside("185.34.106.118")
    dns = cfg["dns"]["rules"]
    assert dns[0] == {"rule_set": ["user-direct"], "server": "local"}
    assert dns[-1]["server"] == "fakeip" and "rule_set" not in dns[-1]   # unknown sites: let smart routing see them


def test_core_mode_keeps_default_route(tmp_path):
    s = Settings(tmp_path / "s.json")
    s.update(capture_mode="tun", routing_mode="smart", direct_bypass="core")
    assert "route_address" not in _tun(cb.build_singbox(s, parse_subscription("\n".join(LINKS))[0]))


def test_system_proxy_gets_voice_tun(tmp_path):
    s = Settings(tmp_path / "s.json")
    s.update(capture_mode="system_proxy", routing_mode="smart")
    nodes = parse_subscription("\n".join(LINKS))[0]
    tun = _tun(cb.build_singbox(s, nodes))
    assert "91.108.4.0/22" in tun["route_address"] and tun["strict_route"] is False
    assert "198.18.0.0/15" not in tun["route_address"]
    assert not any(i["type"] == "tun" for i in cb.build_singbox(s, nodes, tun_allowed=False)["inbounds"])
    s.update(routing_mode="custom")       # no presets -> nothing for the TUN -> no TUN at all
    assert not any(i["type"] == "tun" for i in cb.build_singbox(s, nodes)["inbounds"])


def test_custom_mode_discord_voice_enters_tun(tmp_path):
    import ipaddress
    from nexusvpn.learner import LearnDB
    db = LearnDB()
    db.replace_user("proxy", [("process", "Discord.exe"), ("domain", "discord.com")])
    db.export()
    try:
        s = Settings(tmp_path / "s.json")
        s.update(capture_mode="tun", routing_mode="custom", direct_bypass="full", custom_use_presets=False)
        cfg = cb.build_singbox(s, parse_subscription("\n".join(LINKS))[0])
        nets = [ipaddress.ip_network(c) for c in _tun(cfg)["route_address"]]
        for ip in ("104.29.157.153", "66.22.196.10", "162.159.135.232"):
            assert any(ipaddress.ip_address(ip) in n for n in nets), ip
        rules = cfg["route"]["rules"]
        disc = next(i for i, r in enumerate(rules) if r.get("outbound") == "discord")
        user = next(i for i, r in enumerate(rules) if "user-proxy" in r.get("rule_set", []))
        assert disc < user          # Discord.exe from the user's list still uses the voice group
    finally:
        db.replace_user("proxy", [])
        db.export()


def test_server_switch_keeps_calls(tmp_path):
    s = Settings(tmp_path / "s.json")
    cfg = cb.build_singbox(s, parse_subscription("\n".join(LINKS))[0])
    groups = {o["tag"]: o for o in cfg["outbounds"] if o.get("type") in ("selector", "urltest")}
    assert all(g.get("interrupt_exist_connections") is False for g in groups.values())


class _FakeAPI:
    def __init__(self, delays, now):
        self.delays, self._now, self.selected, self.closed = delays, now, [], []
        self.conns = [{"id": "v", "chains": ["Hy2", "auto-udp", "discord"], "metadata": {"network": "udp"}},
                      {"id": "w", "chains": ["Vless", "proxy"], "metadata": {"network": "tcp"}}]

    def now(self, g):
        return self._now.get(g, "")

    def delay(self, name, url, t):
        return self.delays.get(self._now.get(name, name), -1)

    def group_delay(self, g, url, t):
        return {k: v for k, v in self.delays.items()}

    def select(self, g, n):
        self.selected.append((g, n))
        self._now[g] = n

    def connections(self):
        return {"connections": self.conns}

    def close_connection(self, cid):
        self.closed.append(cid)


def _engine_with(api, tmp_path):
    from nexusvpn.engine import Engine
    eng = Engine.__new__(Engine)
    eng.s = Settings(tmp_path / "s.json")
    eng.api = lambda: api
    eng.emit = lambda *a: None
    eng._voice_fails = eng._last_voice_check = eng._last_all_down = 0
    eng._fails = 0
    eng.restart = lambda *a: (_ for _ in ()).throw(AssertionError("restart"))
    return eng


def test_voice_moves_only_after_two_failures(tmp_path):
    api = _FakeAPI({"Hy2": -1, "Tuic": 90}, {"discord": "auto-udp", "auto-udp": "Hy2", "proxy": "Vless"})
    api.delays["auto-udp"] = -1
    eng = _engine_with(api, tmp_path)
    eng._watch_voice()
    assert api.selected == []                      # one miss is not enough
    eng._last_voice_check = 0
    eng._watch_voice()
    assert api.selected == [("discord", "Tuic")] and api.closed == ["v"]   # only the call reconnects


def test_failover_leaves_calls_alone(tmp_path):
    api = _FakeAPI({"Vless": -1, "Trojan": 120}, {"proxy": "Vless"})
    eng = _engine_with(api, tmp_path)
    eng._failover()
    assert ("proxy", "auto") in api.selected and api.closed == ["w"]
    api2 = _FakeAPI({"Vless": 80}, {"proxy": "Vless"})
    eng2 = _engine_with(api2, tmp_path)
    eng2._failover()
    assert api2.selected == [] and api2.closed == []   # server answers again: nothing is cut
