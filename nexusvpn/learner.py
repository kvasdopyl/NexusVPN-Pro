"""Smart routing: watches live connections, probes reachability direct vs. VPN, remembers verdicts.

How it works
------------
1. Every 2 s the Monitor reads /connections from sing-box.
2. A connection that went DIRECT and looks dead (uploaded data but got ~nothing back,
   or froze in the 14-24 KB band typical for DPI throttling) makes its domain a suspect.
3. The Prober checks the domain twice: through the `probe-direct` inbound and through
   `probe-proxy`. Direct fails + VPN works  =>  domain is learned as "proxy".
   A direct connection that downloaded plenty  =>  domain is learned as "direct".
4. Verdicts live in SQLite and are exported to sing-box local rule-sets, which sing-box
   hot-reloads automatically — no restart, no dropped Discord calls.
5. Dead connections to a freshly-learned domain are closed so the app retries via VPN.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import sqlite3
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from . import paths

log = logging.getLogger("learner")

SECOND_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "net.cn", "org.cn", "com.tr", "com.ua", "org.ua", "net.ua", "in.ua", "kiev.ua",
    "com.ru", "net.ru", "org.ru", "pp.ru", "msk.ru", "spb.ru", "co.kr", "co.in", "co.il", "com.mx",
    "com.ar", "com.tw", "com.hk", "com.sg", "co.nz", "co.za", "com.pl", "com.kz", "org.kz", "com.by",
}
# shared hosting: one blocked customer must not drag the whole platform through the VPN
SHARED_SUFFIXES = {
    "cloudfront.net", "amazonaws.com", "azureedge.net", "azurewebsites.net", "akamaized.net",
    "akamaihd.net", "herokuapp.com", "github.io", "workers.dev", "pages.dev", "vercel.app",
    "netlify.app", "appspot.com", "blogspot.com", "googleusercontent.com", "fastly.net",
    "cdn77.org", "b-cdn.net", "web.app", "firebaseapp.com", "r2.dev", "onrender.com",
    "fly.dev", "glitch.me", "repl.co", "wixsite.com", "tilda.ws", "ngrok.io", "trycloudflare.com",
}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "browser.exe", "brave.exe",
            "vivaldi.exe", "yandex.exe", "iexplore.exe", "arc.exe", "librewolf.exe", "waterfox.exe"}
IGNORE_HOSTS_SUFFIX = (".local", ".lan", ".home", ".internal", ".invalid", ".arpa", "localhost")
BLOCK_PAGE_MARKERS = (b"warning.rt.ru", b"blocked.", b"zapret-info", b"eais.rkn.gov.ru", b"blocklist.rkn")


def base_domain(host: str) -> str:
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    for suf in SHARED_SUFFIXES:
        if host.endswith("." + suf):
            return host
    last2 = ".".join(parts[-2:])
    if last2 in SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def _is_ip(s: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in s else socket.AF_INET, s)
        return True
    except OSError:
        return False


# ======================================================================= storage
class LearnDB:
    """kind: domain | process | ip ; verdict: proxy | direct ; source: auto | user"""

    def __init__(self, path=paths.LEARN_DB):
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS rules(
            kind TEXT NOT NULL, value TEXT NOT NULL, verdict TEXT NOT NULL, source TEXT NOT NULL,
            hits INTEGER DEFAULT 0, fails INTEGER DEFAULT 0, process TEXT DEFAULT '',
            created REAL, updated REAL, checked REAL DEFAULT 0, note TEXT DEFAULT '',
            PRIMARY KEY(kind, value))""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_verdict ON rules(verdict, source)")

    def get(self, kind: str, value: str) -> dict | None:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM rules WHERE kind=? AND value=?", (kind, value))
            row = cur.fetchone()
            return dict(zip([c[0] for c in cur.description], row)) if row else None

    def put(self, kind: str, value: str, verdict: str, source: str = "auto", process: str = "",
            note: str = "") -> bool:
        """Insert/update. Auto verdicts never override user rules. Returns True if changed."""
        now = time.time()
        with self._lock:
            cur = self.get(kind, value)
            if cur and cur["source"] == "user" and source == "auto":
                return False
            if cur and cur["verdict"] == verdict and cur["source"] == source:
                self.conn.execute("UPDATE rules SET hits=hits+1, updated=?, checked=? WHERE kind=? AND value=?",
                                  (now, now, kind, value))
                return False
            self.conn.execute("""INSERT INTO rules(kind,value,verdict,source,hits,process,created,updated,checked,note)
                VALUES(?,?,?,?,1,?,?,?,?,?) ON CONFLICT(kind,value) DO UPDATE SET verdict=excluded.verdict,
                source=excluded.source, process=excluded.process, updated=excluded.updated,
                checked=excluded.checked, note=excluded.note""",
                              (kind, value, verdict, source, process, now, now, now, note))
            return True

    def touch_check(self, kind: str, value: str, failed: bool) -> None:
        with self._lock:
            self.conn.execute("UPDATE rules SET checked=?, fails=CASE WHEN ? THEN fails+1 ELSE 0 END "
                              "WHERE kind=? AND value=?", (time.time(), int(failed), kind, value))

    def delete(self, kind: str, value: str) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM rules WHERE kind=? AND value=?", (kind, value))

    def user_entries(self, verdict: str) -> list[tuple[str, str]]:
        with self._lock:
            return [tuple(r) for r in self.conn.execute(
                "SELECT kind, value FROM rules WHERE source='user' AND verdict=?", (verdict,))]

    def replace_user(self, verdict: str, entries: list[tuple[str, str]]) -> None:
        """Make the user's list for `verdict` exactly `entries` (batch editor save)."""
        now = time.time()
        with self._lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.execute("DELETE FROM rules WHERE source='user' AND verdict=?", (verdict,))
                for kind, value in entries:
                    self.conn.execute(
                        "INSERT INTO rules(kind,value,verdict,source,hits,created,updated,checked,note) "
                        "VALUES(?,?,?,'user',0,?,?,?,'') ON CONFLICT(kind,value) DO UPDATE SET "
                        "verdict=excluded.verdict, source='user', updated=excluded.updated",
                        (kind, value, verdict, now, now, now))
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    def clear_auto(self) -> None:
        with self._lock:
            self.conn.execute("DELETE FROM rules WHERE source='auto'")

    def all(self) -> list[dict]:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM rules ORDER BY updated DESC")
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]

    def values(self, kind: str, verdict: str, source: str | None = None) -> list[str]:
        q, a = "SELECT value FROM rules WHERE kind=? AND verdict=?", [kind, verdict]
        if source:
            q += " AND source=?"
            a.append(source)
        with self._lock:
            return sorted(r[0] for r in self.conn.execute(q, a))

    def stale(self, verdict: str, older_than: float, limit: int = 20) -> list[str]:
        with self._lock:
            return [r[0] for r in self.conn.execute(
                "SELECT value FROM rules WHERE kind='domain' AND verdict=? AND source='auto' AND checked<? "
                "ORDER BY checked LIMIT ?", (verdict, time.time() - older_than, limit))]

    def proxied_ip_count_by_process(self) -> dict[str, int]:
        with self._lock:
            return dict(self.conn.execute(
                "SELECT process, COUNT(*) FROM rules WHERE kind='ip' AND verdict='proxy' AND process!='' "
                "GROUP BY process"))

    def export(self) -> bool:
        """Write sing-box rule-set files. Returns True if anything changed on disk."""
        def rs(*rules):
            body = [r for r in rules if r]
            return {"version": 3, "rules": body or [{"domain": ["placeholder.invalid"]}]}

        def r(key, vals):
            return {key: vals} if vals else None

        def cidr(vals):
            return [v if "/" in v else v + ("/128" if ":" in v else "/32") for v in vals]

        def user(verdict):
            # each field in its own headless rule: fields inside one rule are AND-ed by sing-box
            return rs(r("domain_suffix", self.values("domain", verdict, "user")),
                      r("domain", self.values("full", verdict, "user")),
                      r("domain_keyword", self.values("keyword", verdict, "user")),
                      r("process_name", self.values("process", verdict, "user")))

        files = {
            paths.USER_PROXY_RS: user("proxy"),
            paths.USER_DIRECT_RS: user("direct"),
            paths.USER_PROXY_IP_RS: rs(r("ip_cidr", cidr(self.values("ip", "proxy", "user")))),
            paths.USER_DIRECT_IP_RS: rs(r("ip_cidr", cidr(self.values("ip", "direct", "user")))),
            paths.LEARNED_PROXY_RS: rs(r("domain_suffix", self.values("domain", "proxy", "auto")),
                                       r("process_name", self.values("process", "proxy", "auto"))),
            paths.LEARNED_PROXY_IP_RS: rs(r("ip_cidr", cidr(self.values("ip", "proxy", "auto")))),
            paths.LEARNED_DIRECT_RS: rs(r("domain_suffix", self.values("domain", "direct", "auto"))),
        }
        changed = False
        for path, data in files.items():
            text = json.dumps(data, ensure_ascii=False, indent=1)
            try:
                if path.read_text("utf-8") == text:
                    continue
            except OSError:
                pass
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, "utf-8")
            tmp.replace(path)
            changed = True
        return changed


# ======================================================================= probing
@dataclass
class ProbeResult:
    ok: bool
    reason: str = ""
    bytes: int = 0
    ms: int = 0


def _connect_via(port: int, host: str, dport: int, timeout: float) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(f"CONNECT {host}:{dport} HTTP/1.1\r\nHost: {host}:{dport}\r\n\r\n".encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(1024)
        if not chunk:
            raise ConnectionError("proxy closed")
        resp += chunk
    if b" 200" not in resp.split(b"\r\n", 1)[0]:
        raise ConnectionError(resp.split(b"\r\n", 1)[0].decode(errors="replace"))
    return s


def probe(port: int, host: str, dport: int = 443, timeout: float = 7.0) -> ProbeResult:
    """Fetch a page through the given local inbound and judge whether it really works."""
    t0 = time.monotonic()
    total = 0
    try:
        s = _connect_via(port, host, dport, timeout)
        if dport == 80:
            conn = s
        elif dport == 443 or not _is_ip(host):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(s, server_hostname=None if _is_ip(host) else host)
        else:  # raw TCP endpoint of an app: reaching it is all we can verify
            s.close()
            return ProbeResult(True, "tcp", 0, int((time.monotonic() - t0) * 1000))
        with conn:
            conn.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                         f"AppleWebKit/537.36 Chrome/131 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                         .encode())
            head = b""
            deadline = time.monotonic() + timeout
            while total < 48 * 1024 and time.monotonic() < deadline:
                try:
                    chunk = conn.recv(16384)
                except socket.timeout:
                    if 12 * 1024 <= total <= 26 * 1024:
                        return ProbeResult(False, "throttled (~16KB freeze)", total)
                    break
                if not chunk:
                    break
                if len(head) < 4096:
                    head += chunk[:4096]
                total += len(chunk)
            if total == 0:
                return ProbeResult(False, "no response", 0)
            if any(m in head.lower() for m in BLOCK_PAGE_MARKERS):
                return ProbeResult(False, "ISP block page", total)
            return ProbeResult(True, "ok", total, int((time.monotonic() - t0) * 1000))
    except ssl.SSLError as e:
        return ProbeResult(False, f"tls: {e.reason or e}", total)
    except (OSError, ConnectionError) as e:
        return ProbeResult(False, type(e).__name__ + (f": {e}" if str(e) else ""), total)


# ======================================================================= engine
@dataclass
class _Track:
    first: float
    last_change: float
    down: int
    up: int
    host: str
    ip: str
    port: int
    process: str
    network: str


class Learner:
    POLL = 2.0

    def __init__(self, settings, api_factory: Callable, on_event: Callable[[str, dict], None] | None = None):
        self.s = settings
        self.api_factory = api_factory
        self.db = LearnDB()
        self.on_event = on_event or (lambda *_: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._inflight: set[str] = set()
        self._recent: dict[str, float] = {}     # key -> last probe time
        self._tracks: dict[str, _Track] = {}
        self._lock = threading.Lock()
        self.stats = {"probes": 0, "learned_proxy": 0, "learned_direct": 0}
        self.db.export()

    # ---------- lifecycle ----------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._pool = ThreadPoolExecutor(max_workers=int(self.s["learn_workers"]), thread_name_prefix="probe")
        self._thread = threading.Thread(target=self._loop, name="learner", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    # ---------- public api for UI ----------
    def set_rule(self, kind: str, value: str, verdict: str) -> None:
        value = value.strip().lower() if kind != "process" else value.strip()
        if not value:
            return
        self.db.put(kind, value, verdict, source="user")
        self.apply()

    def remove_rule(self, kind: str, value: str) -> None:
        self.db.delete(kind, value)
        self.apply()

    def apply(self) -> None:
        if self.db.export():
            self.on_event("rules_changed", {})

    def test_now(self, host: str) -> None:
        self._submit(base_domain(host), host, 443, "", manual=True)

    # ---------- monitor ----------
    def _loop(self) -> None:
        last_maint = 0.0
        while not self._stop.wait(self.POLL):
            if not self.s["learn_enabled"] or self.s["routing_mode"] != "smart":
                continue
            try:
                api = self.api_factory()
                data = api.connections()
            except (OSError, ValueError):
                continue
            self._scan(data.get("connections") or [])
            if time.time() - last_maint > 3600:
                last_maint = time.time()
                self._maintenance()

    def _scan(self, conns: list[dict]) -> None:
        now = time.time()
        live = set()
        min_bytes = int(self.s["learn_min_bytes"])
        silent = float(self.s["learn_probe_interval"])
        for c in conns:
            cid = c.get("id")
            md = c.get("metadata") or {}
            chains = c.get("chains") or []
            if not cid or not chains or chains[0] != "direct":
                continue
            if "probe-" in str(md.get("type", "")):
                continue
            live.add(cid)
            host = (md.get("host") or md.get("sniffHost") or "").lower().strip(".")
            down, up = int(c.get("download", 0)), int(c.get("upload", 0))
            proc = re.sub(r" \(.*\)$", "", md.get("processPath") or "").replace("/", "\\").rsplit("\\", 1)[-1]
            t = self._tracks.get(cid)
            if t is None:
                t = _Track(now, now, down, up, host, md.get("destinationIP", ""), int(md.get("destinationPort") or 0),
                           proc, md.get("network", "tcp"))
                self._tracks[cid] = t
                continue
            if down != t.down:
                t.down, t.last_change = down, now
            t.up = up
            if t.network != "tcp":
                continue
            age = now - t.first
            stuck = now - t.last_change
            if t.down >= 256 * 1024 and host:
                self._remember_direct(host)
            elif t.up > 0 and t.down < min_bytes and age > min(8.0, silent):
                self._suspect(t)
            elif 12 * 1024 <= t.down <= 26 * 1024 and stuck > silent:
                self._suspect(t)
        # closed connections: judge by final byte counters
        for cid in list(self._tracks):
            if cid in live:
                continue
            t = self._tracks.pop(cid)
            if t.network == "tcp" and t.up > 300 and t.down < 100 and now - t.first < 30:
                self._suspect(t)
            elif t.down >= 64 * 1024 and t.host:
                self._remember_direct(t.host)

    def _remember_direct(self, host: str) -> None:
        d = base_domain(host)
        if d.endswith(IGNORE_HOSTS_SUFFIX) or _is_ip(d):
            return
        cur = self.db.get("domain", d)
        if cur is None:
            self.db.put("domain", d, "direct", note="трафик идёт напрямую")
            self.stats["learned_direct"] += 1
            self.apply()

    def _suspect(self, t: _Track) -> None:
        if t.host and not _is_ip(t.host):
            if t.host.endswith(IGNORE_HOSTS_SUFFIX):
                return
            d = base_domain(t.host)
            cur = self.db.get("domain", d)
            if cur and (cur["source"] == "user" or cur["verdict"] == "proxy"):
                return
            self._submit(d, t.host, t.port or 443, t.process)
        elif t.ip and self.s["learn_apps"] and t.process and t.process.lower() not in BROWSERS:
            if self.db.get("ip", t.ip):
                return
            self._submit_ip(t.ip, t.port, t.process)

    # ---------- probing ----------
    def _submit(self, domain: str, host: str, port: int, process: str, manual: bool = False) -> None:
        key = f"d:{domain}"
        with self._lock:
            if key in self._inflight or (not manual and time.time() - self._recent.get(key, 0) < 600):
                return
            self._inflight.add(key)
            self._recent[key] = time.time()
        if self._pool:
            self._pool.submit(self._probe_domain, domain, host, port if port in (80, 443) else 443, process, key)

    def _submit_ip(self, ip: str, port: int, process: str) -> None:
        key = f"i:{ip}"
        with self._lock:
            if key in self._inflight or time.time() - self._recent.get(key, 0) < 1800:
                return
            self._inflight.add(key)
            self._recent[key] = time.time()
        if self._pool:
            self._pool.submit(self._probe_ip, ip, port, process, key)

    def _probe_domain(self, domain: str, host: str, port: int, process: str, key: str) -> None:
        from .config_builder import probe_ports
        p_direct, p_proxy = probe_ports(self.s)
        try:
            self.stats["probes"] += 1
            d = probe(p_direct, host, port)
            if d.ok:
                if self.db.get("domain", domain) is None:
                    self.db.put("domain", domain, "direct", process=process, note=f"проверено: {d.ms} мс")
                    self.stats["learned_direct"] += 1
                    self.apply()
                self.on_event("probe", {"domain": domain, "direct": True, "proxy": None})
                return
            # second attempt: transient packet loss must not be mistaken for blocking
            d2 = probe(p_direct, host, port, timeout=10)
            if d2.ok:
                return
            v = probe(p_proxy, host, port, timeout=12)
            self.on_event("probe", {"domain": domain, "direct": False, "proxy": v.ok, "reason": d.reason})
            if v.ok and self.s["learn_auto_apply"]:
                if self.db.put("domain", domain, "proxy", process=process, note=f"напрямую: {d.reason}"):
                    self.stats["learned_proxy"] += 1
                    log.info("learned proxy: %s (%s)", domain, d.reason)
                    self.apply()
                    self._kill_direct(domain)
                    self.on_event("learned", {"domain": domain, "reason": d.reason, "process": process})
        except Exception:  # noqa: BLE001 - a probe must never kill the worker pool
            log.exception("probe %s", domain)
        finally:
            with self._lock:
                self._inflight.discard(key)

    def _probe_ip(self, ip: str, port: int, process: str, key: str) -> None:
        from .config_builder import probe_ports
        p_direct, p_proxy = probe_ports(self.s)
        try:
            d = probe(p_direct, ip, port, timeout=6)
            if d.ok:
                return
            v = probe(p_proxy, ip, port, timeout=10)
            if v.ok and self.s["learn_auto_apply"]:
                self.db.put("ip", ip, "proxy", process=process, note=f"{process}: {d.reason}")
                counts = self.db.proxied_ip_count_by_process()
                if counts.get(process, 0) >= 3 and process.lower() not in BROWSERS:
                    if self.db.put("process", process, "proxy", note="≥3 недоступных адресов напрямую"):
                        self.on_event("learned_app", {"process": process})
                self.apply()
        except Exception:  # noqa: BLE001
            log.exception("probe ip %s", ip)
        finally:
            with self._lock:
                self._inflight.discard(key)

    def _kill_direct(self, domain: str) -> None:
        try:
            api = self.api_factory()
            for c in api.connections().get("connections") or []:
                h = ((c.get("metadata") or {}).get("host") or "").lower()
                if (h == domain or h.endswith("." + domain)) and (c.get("chains") or [""])[0] == "direct":
                    api.close_connection(c["id"])
        except (OSError, ValueError):
            pass

    def _maintenance(self) -> None:
        """Re-validate old verdicts: sites get unblocked, CDNs move."""
        from .config_builder import probe_ports
        p_direct, _ = probe_ports(self.s)
        week = 7 * 86400
        for d in self.db.stale("proxy", week, limit=15):
            if self._stop.is_set():
                return
            ok = probe(p_direct, d).ok and probe(p_direct, d).ok
            self.db.touch_check("domain", d, failed=not ok)
            if ok:
                self.db.put("domain", d, "direct", note="снова доступен напрямую")
        for d in self.db.stale("direct", 4 * week, limit=50):
            self.db.delete("domain", d)   # forget: will be re-learned on next visit
        with self._lock:
            cutoff = time.time() - 3600
            self._recent = {k: v for k, v in self._recent.items() if v > cutoff}
        self.apply()
