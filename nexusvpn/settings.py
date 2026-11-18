"""Persistent application settings with sane defaults and migration-safe loading."""
from __future__ import annotations

import copy
import json
import threading
from typing import Any

from .paths import SETTINGS_FILE, ensure_dirs

DEFAULTS: dict[str, Any] = {
    # ---- engine / capture ----
    "capture_mode": "tun",            # tun | system_proxy | both
    "tun_stack": "mixed",             # mixed | gvisor | system
    "tun_mtu": 1400,                  # <=1400 avoids fragmentation on most LTE/DSL paths
    "tun_ipv4": "172.19.0.1/30",
    "strict_route": True,             # blocks leaks via other interfaces
    "auto_detect_interface": True,
    "endpoint_independent_nat": True,
    "udp_timeout": "5m",              # voice calls survive long silences
    "mixed_port": 2080,
    "clash_api_port": 9090,
    "clash_secret": "",
    "block_quic_direct": True,        # browsers fall back to TCP instead of a dead QUIC
    "ipv6_mode": "off",               # off | prefer | only -> off avoids broken IPv6 leaks

    # ---- routing ----
    "routing_mode": "smart",          # smart | global | custom
    "custom_use_presets": False,      # custom mode: also apply the built-in rule bases
    "learn_enabled": True,
    "learn_auto_apply": True,         # auto-promote proven-blocked domains without asking
    "learn_probe_interval": 20,       # seconds a direct connection may stay silent
    "learn_min_bytes": 4096,
    "learn_workers": 6,
    "learn_apps": True,               # learn per application as well as per domain
    "russian_blocked_presets": True,  # seed with RU-blocked geosite/geoip
    "preset_discord": True,
    "preset_youtube": True,
    "preset_telegram": True,
    "preset_ai": True,                # openai/anthropic/google-ai etc.
    "preset_meta": True,
    "preset_twitter": True,
    "preset_instagram": True,
    "preset_whatsapp": True,
    "preset_steam_direct": True,      # Steam downloads direct = faster
    "discord_isolate": True,          # own selector for Discord, picks a UDP-capable node
    "local_services_direct": True,

    # ---- dns ----
    "dns_local": "77.88.8.8",
    "dns_local_alt": "1.1.1.1",
    "dns_remote": "https://1.1.1.1/dns-query",
    "dns_remote_alt": "https://dns.google/dns-query",
    "dns_strategy": "ipv4_only",
    "dns_fakeip": False,

    # ---- nodes / subscriptions ----
    "subscriptions": [],
    "active_node": "",
    "auto_selector": True,
    "health_check_url": "https://www.gstatic.com/generate_204",
    "health_check_interval": 180,
    "auto_switch_failures": 3,
    "sub_auto_update_hours": 12,

    # ---- quality of life ----
    "core_auto_update": True,
    "rules_auto_update": True,
    "start_minimized": False,
    "openvpn_exe": "",                # empty = auto-detect C:\\Program Files\\OpenVPN\\bin\\openvpn.exe
    "was_connected": True,            # reconnect automatically on next launch
    "autostart": False,
    "log_level": "info",
    "log_max_mb": 8,
    "bypass_lan": True,
    "process_exclusions": [],         # never routed through VPN
    "process_force_vpn": [],          # always through VPN
}


class Settings:
    """Thread-safe settings store with dotted access and atomic saves."""

    def __init__(self, path=None):
        ensure_dirs()
        self._path = path or SETTINGS_FILE
        self._lock = threading.RLock()
        self.data = copy.deepcopy(DEFAULTS)
        self.load()

    # ---------- io ----------
    def load(self) -> None:
        try:
            raw = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        with self._lock:
            self.data.update(raw)
            if self.data.get("routing_mode") in ("rules", "direct"):
                self.data["routing_mode"] = "custom"
            # forward-compatible: add new default keys
            for k, v in DEFAULTS.items():
                self.data.setdefault(k, copy.deepcopy(v))

    def save(self) -> None:
        with self._lock:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), "utf-8")
            tmp.replace(self._path)

    # ---------- access ----------
    def get(self, key: str, default=None):
        with self._lock:
            return self.data.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self.data[key] = value

    def update(self, **kw) -> None:
        with self._lock:
            self.data.update(kw)

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def reset(self) -> None:
        with self._lock:
            self.data = copy.deepcopy(DEFAULTS)
        self.save()
