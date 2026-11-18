"""Catalogue of built-in rule presets (downloaded as binary .srs rule-sets)."""
from __future__ import annotations

import re

SAGER_SITE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs"
SAGER_IP = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs"
RUNET = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/{}"

# setting key -> (list of (tag, url), action)  action: proxy | direct | discord
PRESETS: dict[str, tuple[list[tuple[str, str]], str]] = {
    "russian_blocked_presets": ([
        ("ru-blocked", RUNET.format("rule-set-geosite/geosite-ru-blocked.srs")),
        ("ru-blocked-ip", RUNET.format("rule-set-geoip/geoip-ru-blocked.srs")),
    ], "proxy"),
    "preset_discord": ([("discord", SAGER_SITE.format("discord"))], "discord"),
    "preset_youtube": ([("youtube", SAGER_SITE.format("youtube"))], "proxy"),
    "preset_telegram": ([("telegram", SAGER_SITE.format("telegram"))], "proxy"),
    "preset_ai": ([
        ("openai", SAGER_SITE.format("openai")),
        ("anthropic", SAGER_SITE.format("anthropic")),
        ("google-gemini", SAGER_SITE.format("google-gemini")),
    ], "proxy"),
    "preset_meta": ([("meta", SAGER_SITE.format("meta")), ("facebook", SAGER_SITE.format("facebook"))], "proxy"),
    "preset_twitter": ([("twitter", SAGER_SITE.format("twitter"))], "proxy"),
    "preset_instagram": ([("instagram", SAGER_SITE.format("instagram"))], "proxy"),
    "preset_whatsapp": ([("whatsapp", SAGER_SITE.format("whatsapp"))], "proxy"),
    "preset_steam_direct": ([("steam", SAGER_SITE.format("steam"))], "direct"),
    "local_services_direct": ([("category-ru", SAGER_SITE.format("category-ru")),
                               ("geoip-ru", SAGER_IP.format("ru"))], "direct"),
}

PRESET_TITLES = {
    "russian_blocked_presets": "Заблокированные в РФ (runetfreedom, домены + IP)",
    "preset_discord": "Discord (отдельная группа, голос/видео)",
    "preset_youtube": "YouTube",
    "preset_telegram": "Telegram",
    "preset_ai": "ИИ-сервисы (ChatGPT, Claude, Gemini)",
    "preset_meta": "Meta / Facebook",
    "preset_twitter": "X / Twitter",
    "preset_instagram": "Instagram",
    "preset_whatsapp": "WhatsApp",
    "preset_steam_direct": "Steam — напрямую (быстрые загрузки)",
    "local_services_direct": "Российские сервисы — всегда напрямую",
}

TELEGRAM_CIDRS = [
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22", "91.108.20.0/22",
    "91.108.56.0/22", "95.161.64.0/20", "149.154.160.0/20", "185.76.151.0/24",
    "2001:67c:4e8::/48", "2001:b28:f23c::/47", "2001:b28:f23f::/48",
]

DISCORD_DOMAINS = [
    "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net",
    "discord.co", "discord.gift", "discord.dev", "discord.new", "discordcdn.com",
    "discordstatus.com", "dis.gd", "discord-attachments-uploads-prd.storage.googleapis.com",
]
# Matches Discord.exe, DiscordPTB, DiscordCanary and their Update.exe/helper processes
def game_path_regexes(folders: list[str]) -> list[str]:
    """Folder names -> process_path_regex; a folder anywhere in the program path marks a game."""
    out = []
    for f in folders:
        f = f.strip().strip("\\/").replace("/", "\\")
        if f:
            # "Call of Duty" also covers "Call of Duty HQ", "Call of Duty Black Ops 7"
            out.append(r"(?i)\\" + re.escape(f) + r"[^\\]*\\")
    return out


DISCORD_PROCESS_REGEX = r"(?i)\\Discord(PTB|Canary|Development)?\\"
DISCORD_PROCESSES = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe", "DiscordDevelopment.exe"]

ALL_TAGS = {tag: url for items, _ in PRESETS.values() for tag, url in items}


def enabled_presets(settings) -> list[tuple[str, str, str]]:
    """[(tag, url, action)] for every preset switched on in settings."""
    out = []
    for key, (items, action) in PRESETS.items():
        if settings.get(key):
            out.extend((tag, url, action) for tag, url in items)
    return out
