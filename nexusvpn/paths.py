import os
import sys
from pathlib import Path

APP_NAME = "NexusVPN Pro"
APP_SHORT = "NexusVPN"
APP_VERSION = "2.3.0"
APP_DESCRIPTION = ("NexusVPN Pro — Профессиональный VPN-клиент для Windows с интеллектуальной самообучающейся "
                   "маршрутизацией (Smart Auto-Split Tunneling) и поддержкой всех современных протоколов")


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()
PORTABLE = (BASE_DIR / "portable.flag").exists()

if PORTABLE or os.name != "nt":
    DATA_DIR = BASE_DIR / "data"
else:
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / APP_NAME

CORES_DIR = DATA_DIR / "cores"
RULES_DIR = DATA_DIR / "rules"
LOGS_DIR = DATA_DIR / "logs"
RUN_DIR = DATA_DIR / "run"
BACKUP_DIR = DATA_DIR / "backup"

SETTINGS_FILE = DATA_DIR / "settings.json"
NODES_FILE = DATA_DIR / "nodes.json"
LEARN_DB = DATA_DIR / "learned.sqlite"
SINGBOX_CONFIG = RUN_DIR / "sing-box.json"
XRAY_CONFIG = RUN_DIR / "xray.json"
MIHOMO_CONFIG = RUN_DIR / "mihomo.yaml"
OVPN_DIR = RUN_DIR / "openvpn"
LEARNED_PROXY_RS = RULES_DIR / "learned-proxy.json"
LEARNED_PROXY_IP_RS = RULES_DIR / "learned-proxy-ip.json"
LEARNED_DIRECT_RS = RULES_DIR / "learned-direct.json"
USER_PROXY_RS = RULES_DIR / "user-proxy.json"
USER_DIRECT_RS = RULES_DIR / "user-direct.json"
USER_PROXY_IP_RS = RULES_DIR / "user-proxy-ip.json"
USER_DIRECT_IP_RS = RULES_DIR / "user-direct-ip.json"
PID_FILE = RUN_DIR / "cores.pid"

EXE = ".exe" if os.name == "nt" else ""


def core_path(name: str) -> Path:
    return CORES_DIR / name / f"{name}{EXE}"


def ensure_dirs() -> None:
    for d in (DATA_DIR, CORES_DIR, RULES_DIR, LOGS_DIR, RUN_DIR, BACKUP_DIR, OVPN_DIR):
        d.mkdir(parents=True, exist_ok=True)
