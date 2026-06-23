#!/usr/bin/env python3
"""
Murmur - decoy traffic generator for the Raspberry Pi Zero 2 W.

Runs as a LAN client behind a GL.iNet router that already runs Pi-hole.
It emits two layers of plausible decoy traffic so an ISP or data broker
can't cleanly profile the household's real interests:

  * DNS layer   - lightweight lookups to popular real domains, shaped to a
                  household rhythm. These hit the router's Pi-hole (the LAN's
                  resolver), so they land in the SAME query log as real traffic.
  * Browser layer - shallow page loads with a browser-impersonated TLS
                  fingerprint that follow same-site links and fetch a sample of
                  each page's assets, producing the realistic destination
                  fan-out and byte volumes a real visit creates.

It does NOT render JavaScript. Everything it fakes is the stuff the ISP can
actually see; the stuff it skips lives above the encryption.

This is the engine. The dashboard lives in dashboard.py and is started here as
a thread. One process, one systemd service.
"""
import asyncio
import json
import math
import os
import random
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
import dns.resolver
from curl_cffi.requests import AsyncSession

import dashboard

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = os.environ.get("MURMUR_CONFIG", "/etc/murmur/config.json")
START_TS = time.time()

DEFAULTS = {
    "resolver": "auto",                # "auto" = use the default gateway (the router/Pi-hole)
    "dashboard_port": 8787,
    "data_dir": "/var/lib/murmur",
    "seeds_file": str(APP_DIR / "seeds.json"),
    "concurrency": 3,
    "impersonate": ["chrome", "chrome131", "edge", "safari"],
    "dns_layer": {"enabled": True, "base_qpm": 18},
    "browser_layer": {
        "enabled": True,
        "active_start": 7,
        "active_end": 23,
        "session_gap_seconds": [25, 95],
        "links_per_session": [1, 3],
        "dwell_seconds": [2, 7],
        "asset_sample": 0.5,
        "max_assets": 25,
        "timeout": 12,
    },
    "ipv6": False,
    "bandwidth": {"monthly_cap_gb": 1200, "throttle_at_pct": 90},
    "rhythm": {"overnight_floor": 0.12},
    "retention_days": 3,
    "ttl_hardening": False,
}

LINK_RE = re.compile(r'href=["\']([^"\'>#]+)', re.I)
ASSET_RE = re.compile(
    r'(?:src|href)=["\']([^"\'>]+\.(?:js|css|png|jpe?g|webp|gif|svg|woff2?|ico))', re.I
)


# --------------------------------------------------------------------------- #
#  Config
# --------------------------------------------------------------------------- #
def deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config():
    cfg = dict(DEFAULTS)
    p = Path(CONFIG_PATH)
    if p.exists():
        try:
            cfg = deep_merge(DEFAULTS, json.loads(p.read_text()))
        except Exception as e:
            print(f"[murmur] bad config, using defaults: {e}", flush=True)
    return cfg


def save_config(cfg):
    try:
        Path(CONFIG_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(CONFIG_PATH).write_text(json.dumps(cfg, indent=2))
    except Exception as e:
        print(f"[murmur] could not save config: {e}", flush=True)


def detect_gateway():
    """Find the default-gateway IP - i.e. the router running Pi-hole."""
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except Exception:
        pass
    return "192.168.8.1"  # GL.iNet default


# --------------------------------------------------------------------------- #
#  Database
# --------------------------------------------------------------------------- #
class DB:
    def __init__(self, path):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.cx = sqlite3.connect(path, check_same_thread=False)
        self.cx.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        with self.lock:
            self.cx.executescript(
                """
                CREATE TABLE IF NOT EXISTS events(
                  id INTEGER PRIMARY KEY, ts REAL, layer TEXT, kind TEXT,
                  domain TEXT, bytes INTEGER, ok INTEGER, cat TEXT);
                CREATE TABLE IF NOT EXISTS usage(
                  month TEXT PRIMARY KEY, bytes INTEGER, requests INTEGER);
                CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
                """
            )
            self.cx.commit()

    def log(self, layer, kind, domain, nbytes=0, ok=1, cat=""):
        month = datetime.now().strftime("%Y-%m")
        with self.lock:
            self.cx.execute(
                "INSERT INTO events(ts,layer,kind,domain,bytes,ok,cat) VALUES(?,?,?,?,?,?,?)",
                (time.time(), layer, kind, domain, int(nbytes), int(ok), cat),
            )
            self.cx.execute(
                "INSERT INTO usage(month,bytes,requests) VALUES(?,?,1) "
                "ON CONFLICT(month) DO UPDATE SET bytes=bytes+?, requests=requests+1",
                (month, int(nbytes), int(nbytes)),
            )
            self.cx.commit()

    def month_bytes(self):
        month = datetime.now().strftime("%Y-%m")
        with self.lock:
            row = self.cx.execute(
                "SELECT bytes FROM usage WHERE month=?", (month,)
            ).fetchone()
        return row[0] if row else 0

    def prune(self, days):
        cutoff = time.time() - days * 86400
        with self.lock:
            self.cx.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self.cx.commit()


# --------------------------------------------------------------------------- #
#  Shared runtime state (read by the dashboard thread)
# --------------------------------------------------------------------------- #
class State:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.paused = False
        self.resolver_ip = None
        self.ipv6_ok = 0          # count of successful v6 lookups/fetches
        self.start_ts = START_TS
        self.reload_seeds = False
        # health window (rolling on recent browser fetches)
        self.web_attempts = 0
        self.web_failures = 0

    def health_pct(self):
        if self.web_attempts < 5:
            return 1.0
        return max(0.0, 1.0 - self.web_failures / self.web_attempts)

    def note_web(self, ok):
        # decay the window so the figure stays "recent"
        if self.web_attempts >= 400:
            self.web_attempts //= 2
            self.web_failures //= 2
        self.web_attempts += 1
        if not ok:
            self.web_failures += 1


# --------------------------------------------------------------------------- #
#  Seeds / personas
# --------------------------------------------------------------------------- #
def load_seeds(path):
    data = json.loads(Path(path).read_text())
    flat = []
    for cat, doms in data.items():
        for d in doms:
            flat.append((d, cat))
    return data, flat


PERSONAS = [
    {"name": "commuter", "weights": {"news": 3, "travel": 2, "reference": 1}},
    {"name": "shopper", "weights": {"shopping": 3, "finance": 1, "tech": 1}},
    {"name": "fan", "weights": {"sports": 3, "social": 2, "streaming": 1}},
    {"name": "hobbyist", "weights": {"food": 2, "reference": 2, "tech": 2}},
]


def weighted_domain(persona, by_cat):
    pool = []
    for cat, w in persona["weights"].items():
        for d in by_cat.get(cat, []):
            pool.extend([(d, cat)] * w)
    if not pool:
        # fall back to any seed
        allc = [(d, c) for c, ds in by_cat.items() for d in ds]
        return random.choice(allc)
    return random.choice(pool)


# --------------------------------------------------------------------------- #
#  Rhythm
# --------------------------------------------------------------------------- #
def diurnal(h):
    return (
        0.08
        + 1.00 * math.exp(-((h - 8.5) ** 2) / 7)
        + 0.60 * math.exp(-((h - 13) ** 2) / 9)
        + 1.15 * math.exp(-((h - 20.5) ** 2) / 6)
    )


DIURNAL_MAX = max(diurnal(h) for h in range(24))


def rhythm_factor(cfg):
    h = datetime.now().hour
    floor = cfg["rhythm"]["overnight_floor"]
    return max(floor, diurnal(h) / DIURNAL_MAX)


# --------------------------------------------------------------------------- #
#  DNS layer
# --------------------------------------------------------------------------- #
async def dns_layer(state, by_cat):
    cfg = state.cfg
    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = [state.resolver_ip]
    res.lifetime = 5.0
    allc = [(d, c) for c, ds in by_cat.items() for d in ds]
    while True:
        try:
            if state.paused or not cfg["dns_layer"]["enabled"]:
                await asyncio.sleep(3)
                continue
            qpm = max(1, cfg["dns_layer"]["base_qpm"] * rhythm_factor(cfg))
            await asyncio.sleep(60.0 / qpm * random.uniform(0.6, 1.4))
            domain, cat = random.choice(allc)
            try:
                await res.resolve(domain, "A")
                state.db.log("dns", "query", domain, 0, 1, cat)
            except Exception:
                state.db.log("dns", "query", domain, 0, 0, cat)
            if cfg["ipv6"]:
                try:
                    await res.resolve(domain, "AAAA")
                    state.ipv6_ok += 1
                except Exception:
                    pass
        except Exception as e:
            print(f"[dns] {e}", flush=True)
            await asyncio.sleep(2)


# --------------------------------------------------------------------------- #
#  Browser layer
# --------------------------------------------------------------------------- #
def same_host_links(html, host):
    out = set()
    for m in LINK_RE.findall(html or ""):
        if m.startswith("/") and not m.startswith("//"):
            out.add(f"https://{host}{m}")
        elif m.startswith(f"https://{host}"):
            out.add(m.split("#")[0])
    return [u for u in out if len(u) < 300][:40]


def page_assets(html, host):
    out = []
    for m in ASSET_RE.findall(html or ""):
        if m.startswith("http"):
            out.append(m)
        elif m.startswith("//"):
            out.append("https:" + m)
        elif m.startswith("/"):
            out.append(f"https://{host}{m}")
    # de-dup, keep order
    seen, uniq = set(), []
    for u in out:
        if u not in seen and len(u) < 400:
            seen.add(u)
            uniq.append(u)
    return uniq


async def fetch(session, url, state, imp, referer=None, cat="", timeout=12):
    headers = {"Referer": referer} if referer else {}
    try:
        r = await session.get(url, impersonate=imp, headers=headers, timeout=timeout)
        n = len(r.content or b"")
        host = url.split("/")[2] if "://" in url else url
        state.db.log("web", "fetch", host, n, 1, cat)
        return r.text if "text/html" in r.headers.get("content-type", "") else "", n
    except Exception:
        host = url.split("/")[2] if "://" in url else url
        state.db.log("web", "fetch", host, 0, 0, cat)
        return "", 0


async def session_task(state, by_cat, sem):
    cfg = state.cfg
    b = cfg["browser_layer"]
    persona = random.choice(PERSONAS)
    domain, cat = weighted_domain(persona, by_cat)
    imp = random.choice(cfg["impersonate"])
    async with sem:
        try:
            async with AsyncSession() as s:
                home = f"https://{domain}"
                html, n = await fetch(s, home, state, imp, cat=cat, timeout=b["timeout"])
                state.note_web(n > 0)
                collected = [(html, domain)]
                # follow a few same-site links with referers
                links = same_host_links(html, domain)
                hops = random.randint(*b["links_per_session"])
                ref = home
                for _ in range(hops):
                    if not links:
                        break
                    nxt = random.choice(links)
                    await asyncio.sleep(random.uniform(*b["dwell_seconds"]))
                    h2, n2 = await fetch(s, nxt, state, imp, referer=ref, cat=cat,
                                         timeout=b["timeout"])
                    state.note_web(n2 > 0)
                    collected.append((h2, domain))
                    ref = nxt
                    links = same_host_links(h2, domain) or links
                # asset fan-out: this is what makes it look like a real visit
                assets = []
                for h, host in collected:
                    assets.extend(page_assets(h, host))
                random.shuffle(assets)
                k = min(int(len(assets) * b["asset_sample"]), b["max_assets"])
                tasks = [fetch(s, a, state, imp, referer=home, cat=cat,
                               timeout=b["timeout"]) for a in assets[:k]]
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            print(f"[web] session error: {e}", flush=True)


async def browser_layer(state, by_cat):
    cfg = state.cfg
    b = cfg["browser_layer"]
    sem = asyncio.Semaphore(cfg["concurrency"])
    cap = cfg["bandwidth"]["monthly_cap_gb"] * (10 ** 9)
    throttle = cfg["bandwidth"]["throttle_at_pct"] / 100.0
    while True:
        try:
            now_h = datetime.now().hour
            active = b["active_start"] <= now_h < b["active_end"]
            if state.paused or not b["enabled"] or not active:
                await asyncio.sleep(20)
                continue
            if state.db.month_bytes() > cap * throttle:
                state.db.log("web", "note", "throttling near monthly cap", 0, 1, "")
                await asyncio.sleep(300)
                continue
            gap = random.uniform(*b["session_gap_seconds"]) / rhythm_factor(cfg)
            await asyncio.sleep(gap)
            asyncio.create_task(session_task(state, by_cat, sem))
        except Exception as e:
            print(f"[web] {e}", flush=True)
            await asyncio.sleep(5)


async def housekeeping(state):
    while True:
        try:
            state.db.prune(state.cfg["retention_days"])
            if state.reload_seeds:
                state.reload_seeds = False
                state.web_attempts = state.web_failures = 0
        except Exception:
            pass
        await asyncio.sleep(3600)


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
async def main_async():
    cfg = load_config()
    db = DB(str(Path(cfg["data_dir"]) / "murmur.db"))
    state = State(cfg, db)
    state.resolver_ip = detect_gateway() if cfg["resolver"] == "auto" else cfg["resolver"]
    by_cat, _ = load_seeds(cfg["seeds_file"])
    state.seeds_by_cat = by_cat

    print(f"[murmur] resolver (Pi-hole) = {state.resolver_ip}", flush=True)
    print(f"[murmur] dashboard on http://0.0.0.0:{cfg['dashboard_port']}", flush=True)

    # dashboard runs in its own thread, reading the same DB + shared state
    dashboard.start(state, APP_DIR, save_config)

    await asyncio.gather(
        dns_layer(state, by_cat),
        browser_layer(state, by_cat),
        housekeeping(state),
    )


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[murmur] stopped", flush=True)


if __name__ == "__main__":
    main()
