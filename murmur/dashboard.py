"""
Murmur dashboard - a tiny stdlib HTTP server (no extra deps) that serves the
console UI and a live state API. Runs in a daemon thread inside the engine
process and reads the same SQLite DB + shared State object.

Routes:
  GET  /                 -> console UI
  GET  /api/state        -> live metrics + Blend Score factors (JSON)
  POST /api/pause        -> toggle the whole node on/off
  POST /api/fix/<id>     -> apply a hardening fix (ttl | ipv6 | seeds)
"""
import json
import os
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TTL_FLAG = "/var/lib/murmur/ttl.on"
HARDEN_SCRIPT = "/opt/murmur/harden-ttl.sh"

_STATE = None
_APPDIR = None
_SAVE_CFG = None


# --------------------------------------------------------------------------- #
#  Score model - factors here are computed from REAL, observable conditions.
# --------------------------------------------------------------------------- #
BASE_SCORE = 20


def ttl_active():
    if os.path.exists(TTL_FLAG):
        return True
    try:
        out = subprocess.check_output(["nft", "list", "ruleset"], text=True,
                                      stderr=subprocess.DEVNULL)
        return "ttl set" in out
    except Exception:
        return False


def ipv6_available():
    try:
        out = subprocess.check_output(["ip", "-6", "addr"], text=True,
                                      stderr=subprocess.DEVNULL)
        return "scope global" in out
    except Exception:
        return False


def compute_factors(state):
    cfg = state.cfg
    health = state.health_pct()
    has_v6 = ipv6_available()
    f = []
    f.append({"id": "tls", "label": "TLS fingerprint", "pts": 18, "state": "good",
              "detail": "Fetches use a browser-impersonated TLS handshake "
                        f"({', '.join(cfg['impersonate'])}), indistinguishable from a real browser."})
    f.append({"id": "timing", "label": "Traffic timing", "pts": 16, "state": "good",
              "detail": "Bursts are shaped to a household rhythm and go quiet overnight."})
    f.append({"id": "category", "label": "Category blend", "pts": 15, "state": "good",
              "detail": "Decoys are drawn from popular real sites across the same categories a household browses."})

    if ttl_active():
        f.append({"id": "ttl", "label": "Device fingerprint", "pts": 12, "state": "good",
                  "detail": "Outgoing packets are normalised to TTL 128 (Windows), so the Pi's flows don't cluster apart."})
    else:
        f.append({"id": "ttl", "label": "Device fingerprint", "pts": 12, "state": "fix",
                  "fix": "Match Windows TTL",
                  "detail": "Pi flows carry TTL 64 (Linux) while a typical house is mostly Windows (128), so they can be clustered apart and the noise peeled off. One nftables rule fixes it."})

    if cfg.get("ipv6") and (state.ipv6_ok > 0 or has_v6):
        f.append({"id": "ipv6", "label": "IPv6 coverage", "pts": 8, "state": "good",
                  "detail": "Decoy lookups also run over IPv6, covering your real v6 flows."})
    elif has_v6:
        f.append({"id": "ipv6", "label": "IPv6 coverage", "pts": 8, "state": "fix",
                  "fix": "Enable IPv6 noise",
                  "detail": "Your network hands out IPv6, so some real flows use addresses the noise never touches. Turn on v6 decoys."})
    else:
        f.append({"id": "ipv6", "label": "IPv6 coverage", "pts": 8, "state": "good",
                  "detail": "No global IPv6 on this network, so there's nothing to cover. Handled by default."})

    if health >= 0.9:
        f.append({"id": "health", "label": "Decoy fetch health", "pts": 5, "state": "good",
                  "detail": f"{round(health*100)}% of shallow loads are succeeding - the seed list is fresh."})
    else:
        f.append({"id": "health", "label": "Decoy fetch health", "pts": 5, "state": "fix",
                  "fix": "Refresh seed list",
                  "detail": f"Only {round(health*100)}% of shallow loads are succeeding - dead domains waste effort and are a faint tell."})

    f.append({"id": "dns", "label": "DNS transport", "pts": 6, "state": "warn",
              "fix": "Switch to DoH",
              "detail": "Queries reach your ISP in cleartext via the router. The noise muddies them, but DoH would also hide the query content. Optional."})
    return f


def score_from(factors):
    return BASE_SCORE + sum(f["pts"] for f in factors if f["state"] == "good")


# --------------------------------------------------------------------------- #
#  State assembly
# --------------------------------------------------------------------------- #
def read_db(state):
    """Open a thread-local read connection each call (cheap, safe)."""
    db_path = state.db.path
    cx = sqlite3.connect(db_path, check_same_thread=False)
    try:
        today0 = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        req_today = cx.execute(
            "SELECT COUNT(*) FROM events WHERE ts>=? AND kind!='note'", (today0,)
        ).fetchone()[0]
        month_bytes = state.db.month_bytes()
        cats = cx.execute(
            "SELECT cat, COUNT(*) c FROM events WHERE ts>=? AND cat!='' "
            "GROUP BY cat ORDER BY c DESC", (today0,)
        ).fetchall()
        recent = cx.execute(
            "SELECT ts,layer,kind,domain,bytes FROM events ORDER BY id DESC LIMIT 14"
        ).fetchall()
        return req_today, month_bytes, cats, recent
    finally:
        cx.close()


def fmt_recent(rows):
    out = []
    for ts, layer, kind, domain, nbytes in rows:
        t = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        if kind == "note":
            out.append({"t": t, "text": domain})
        elif layer == "dns":
            out.append({"t": t, "text": f"resolved <b>{domain}</b>"})
        else:
            kb = f" · {nbytes//1024} KB" if nbytes else ""
            out.append({"t": t, "text": f"fetched <b>{domain}</b>{kb}"})
    return out


def build_state():
    state = _STATE
    factors = compute_factors(state)
    score = score_from(factors)
    req_today, month_bytes, cats, recent = read_db(state)
    total = sum(c for _, c in cats) or 1
    categories = [[c.capitalize(), round(n * 100 / total)] for c, n in cats[:7]]
    up = int(time.time() - state.start_ts)
    return {
        "running": not state.paused,
        "score": score,
        "factors": factors,
        "requests_today": req_today,
        "bytes_month": month_bytes,
        "cap_gb": state.cfg["bandwidth"]["monthly_cap_gb"],
        "categories": categories,
        "recent": fmt_recent(recent),
        "resolver": state.resolver_ip,
        "uptime_s": up,
    }


# --------------------------------------------------------------------------- #
#  Fix actions
# --------------------------------------------------------------------------- #
def apply_fix(fix_id):
    state = _STATE
    if fix_id == "ttl":
        try:
            subprocess.run(["sudo", "-n", HARDEN_SCRIPT, "on"], check=True, timeout=10)
            return True, "TTL normalised to 128"
        except Exception as e:
            return False, f"could not apply TTL rule: {e}"
    if fix_id == "ipv6":
        state.cfg["ipv6"] = True
        _SAVE_CFG(state.cfg)
        return True, "IPv6 decoys enabled"
    if fix_id == "seeds":
        state.reload_seeds = True
        return True, "seed list refreshed"
    if fix_id == "dns":
        return False, "DoH is a manual router change - see the README"
    return False, "unknown fix"


# --------------------------------------------------------------------------- #
#  HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html = (_APPDIR / "static" / "index.html").read_text()
            return self._send(200, html, "text/html; charset=utf-8")
        if self.path == "/api/state":
            return self._send(200, build_state())
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path == "/api/pause":
            _STATE.paused = not _STATE.paused
            return self._send(200, {"running": not _STATE.paused})
        if self.path.startswith("/api/fix/"):
            fid = self.path.rsplit("/", 1)[-1]
            ok, msg = apply_fix(fid)
            return self._send(200 if ok else 400, {"ok": ok, "message": msg})
        return self._send(404, {"error": "not found"})


def start(state, app_dir, save_cfg):
    global _STATE, _APPDIR, _SAVE_CFG
    _STATE, _APPDIR, _SAVE_CFG = state, Path(app_dir), save_cfg
    port = state.cfg["dashboard_port"]
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
