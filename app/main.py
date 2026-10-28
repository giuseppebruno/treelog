import base64
import gc
import gzip
import hmac
import json
import os
import signal
import sys
import threading
import time
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from classify import CATEGORIES
from engine import Engine
from alerts import AlertManager
from geo import Geo, resolve_provider

HERE = os.path.dirname(os.path.abspath(__file__))


def env(name, default):
    return os.environ.get(name) or default   # unset or empty: use the default


def split(v):
    return [x.strip() for x in v.split(",") if x.strip()]


CFG = {
    "access_globs": split(env("ACCESS_LOGS", "/logs/**/*access*.log*")),
    "error_globs": split(env("ERROR_LOGS", "/logs/**/*error*.log*")),
    "vhost_regex": env("VHOST_REGEX", ""),
    "max_vhosts": int(env("MAX_VHOSTS", "50")),
    "access_regex": env("ACCESS_REGEX", ""),
    "ignore_regex": env("IGNORE_REGEX", ""),
    "ignore_ips": split(env("IGNORE_IPS", "")),
    "retention": int(env("RETENTION_HOURS", "48")) * 3600,
    "cap": int(env("MAX_KEYS_PER_BUCKET", "200")),
    "backfill_mb": int(env("BACKFILL_MB", "200")),
    "poll": float(env("POLL_SECONDS", "2")),
    "save_every": int(env("SAVE_EVERY_SECONDS", "60")),
    "state_file": env("STATE_FILE", "/data/state.json"),
}
# time resolution: about 288 buckets over the retention (600 s for 48 h), in multiples of 5 minutes
CFG["bucket"] = int(env("BUCKET_SECONDS", str(max(600, -(-CFG["retention"] // 288 // 300) * 300))))


def flag(name, default):
    return env(name, default).strip().lower() in ("1", "true", "yes", "on")


WATCH = {
    "keep_minutes": int(env("ALERT_WINDOW_MINUTES", "10")) + 5,
    "behavior_minutes": int(env("BEHAVIOR_WINDOW_MINUTES", "10")),
    "max_ips": int(env("MAX_TRACKED_IPS", "5000")),
    "scan_min": int(env("SCAN_MIN", "30")),        # distinct paths with 4xx within the window
    "brute_min": int(env("BRUTE_MIN", "15")),      # login POSTs (or 401s) within the window
    "flood_min": int(env("FLOOD_MIN", "600")),     # requests from a single IP within the window
    "attack_min": int(env("ATTACK_MIN", "20")),    # hostile requests from a single IP within the window
}
WATCH["span"] = max(WATCH["keep_minutes"], WATCH["behavior_minutes"]) * 60 + 120
CFG["watch"] = WATCH
ALERT = {
    "name": env("ALERT_NAME", ""),
    "dashboard_url": env("ALERT_DASHBOARD_URL", ""),
    "ntfy_url": env("ALERT_NTFY_URL", ""), "ntfy_token": env("ALERT_NTFY_TOKEN", ""),
    "telegram_token": env("ALERT_TELEGRAM_TOKEN", ""), "telegram_chat_id": env("ALERT_TELEGRAM_CHAT_ID", ""),
    "telegram_api": env("ALERT_TELEGRAM_API", "https://api.telegram.org"),
    "webhook_url": env("ALERT_WEBHOOK_URL", ""), "webhook_secret": env("ALERT_WEBHOOK_SECRET", ""),
    "rules": split(env("ALERT_RULES", "server_errors,exposed,error_rate,spike")),
    "window_minutes": int(env("ALERT_WINDOW_MINUTES", "10")),
    "cooldown_minutes": int(env("ALERT_COOLDOWN_MINUTES", "60")),
    "eval_seconds": int(env("ALERT_EVAL_SECONDS", "30")),
    "notify_resolved": flag("ALERT_NOTIFY_RESOLVED", "1"),
    "attack_5xx_min": int(env("ALERT_ATTACK_5XX_MIN", "5")),
    "exposed_categories": split(env("ALERT_EXPOSED_CATEGORIES", "rce,sqli,traversal")),
    "exposed_min": int(env("ALERT_EXPOSED_MIN", "3")),
    "error_rate": float(env("ALERT_5XX_RATE", "0.05")),
    "min_requests": int(env("ALERT_MIN_REQUESTS", "50")),
    "spike_min": int(env("ALERT_SPIKE_MIN", "200")),
    "spike_factor": float(env("ALERT_SPIKE_FACTOR", "4")),
    "silence_minutes": int(env("ALERT_SILENCE_MINUTES", "0")),
}
_DATA_DIR = os.path.dirname(env("STATE_FILE", "/data/state.json")) or "."
GEO = {
    "provider": env("GEO_PROVIDER", "auto"),            # auto | mmdb | api | off
    "token": env("IPINFO_TOKEN", "").strip(),
    "data_dir": _DATA_DIR,
    "data_db": os.path.join(_DATA_DIR, "ipinfo_lite.mmdb"),
    "cache_file": env("GEO_CACHE_FILE", os.path.join(_DATA_DIR, "geo_cache.json")),
    "update_hours": int(env("GEO_UPDATE_HOURS", "168")),
    "db_url": env("GEO_DB_URL", "https://ipinfo.io/data/ipinfo_lite.mmdb"),
    "api_url": env("GEO_API_URL", "https://api.ipinfo.io/lite"),
    "api_rps": float(env("GEO_API_RPS", "10")),
    "cache_max": int(env("GEO_CACHE_MAX", "50000")),
    "queue_max": 2000,
}
GEO["provider"] = resolve_provider(GEO)
PORT = int(env("PORT", "8080"))
TOP_ROWS = int(env("TOP_ROWS", "800"))
USER, PASS = env("DASH_USER", ""), env("DASH_PASS", "")

ENGINE = None
ALERTS = None
GEOIP = Geo(GEO)
_cache = {}
_cache_lock = threading.Lock()

STATIC = {}
for name, ctype in (("index.html", "text/html; charset=utf-8"), ("app.js", "text/javascript; charset=utf-8"),
                    ("style.css", "text/css; charset=utf-8"),
                    ("favicon.svg", "image/svg+xml")):
    with open(os.path.join(HERE, "static", name), "rb") as fh:
        STATIC["/" if name == "index.html" else "/" + name] = (fh.read(), ctype)

SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
}


def api_data(window, vhost):
    now = time.time()
    with _cache_lock:
        hit = _cache.get((window, vhost))
        if hit and now - hit[0] < (1 if GEOIP.pending() else 5):  # unresolved API lookups: refresh sooner
            return hit[1]
    snap = ENGINE.store.snapshot(window, TOP_ROWS, vhost)
    snap["categories"] = CATEGORIES
    if GEOIP.enabled:
        geo = {}
        for row in snap["ips"]:
            ip = row[1]
            if ip not in geo and ip != "(other)":
                g = GEOIP.lookup(ip)
                if g:
                    geo[ip] = g
        snap["geo"] = geo
    raw = json.dumps(snap, separators=(",", ":")).encode()
    with _cache_lock:
        _cache[(window, vhost)] = (now, raw)
        if len(_cache) > 64:
            _cache.pop(next(iter(_cache)))
    return raw


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "treelog"
    timeout = 30  # idle keep-alive connections are closed instead of holding a thread forever

    def log_message(self, *a):
        pass

    def _authorized(self):
        if not USER:
            return True
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                u, _, p = base64.b64decode(h[6:]).decode().partition(":")
                return hmac.compare_digest(u, USER) & hmac.compare_digest(p, PASS)
            except Exception:
                pass
        return False

    def _send(self, code, body, ctype, extra=None):
        if len(body) > 1024 and "gzip" in self.headers.get("Accept-Encoding", "") and ctype.startswith(("application/json", "text/")):
            body = gzip.compress(body, 3)
            extra = dict(extra or {}, **{"Content-Encoding": "gzip"})
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**SEC_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self._authorized():
            return self._send(401, b"auth required", "text/plain", {"WWW-Authenticate": 'Basic realm="treelog"'})
        # custom header: another origin cannot send it without a CORS preflight (CSRF protection)
        if self.path == "/api/alerts/test" and self.headers.get("X-Requested-With") == "fetch":
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(min(n, 4096))
            return self._send(200, json.dumps(ALERTS.send_test()).encode(), "application/json", {"Cache-Control": "no-store"})
        self._send(404, b"not found", "text/plain")

    def do_GET(self):
        if self.path == "/healthz":  # unauthenticated: used by the Docker HEALTHCHECK
            return self._send(200, b"ok", "text/plain")
        if not self._authorized():
            return self._send(401, b"auth required", "text/plain", {"WWW-Authenticate": 'Basic realm="treelog"'})
        path, _, query = self.path.partition("?")
        if path in STATIC:
            body, ctype = STATIC[path]
            return self._send(200, body, ctype, {"Cache-Control": "no-cache"})
        if path == "/api/data":
            q = parse_qs(query)
            try:
                w = int(q.get("w", ["86400"])[0])
            except ValueError:
                w = 86400
            vhost = q.get("vhost", [""])[0][:100] or None
            w = min(max(w, 600), CFG["retention"])
            w = max(CFG["bucket"], w // 300 * 300)  # quantize: fewer cache keys
            return self._send(200, api_data(w, vhost), "application/json", {"Cache-Control": "no-store"})
        if path == "/api/alerts":
            return self._send(200, json.dumps(ALERTS.status()).encode(), "application/json", {"Cache-Control": "no-store"})
        if path == "/api/offenders":
            wc = ENGINE.watch.cfg
            items = ENGINE.watch.offenders(time.time())
            if GEOIP.enabled:
                for o in items:
                    o["geo"] = GEOIP.lookup(o["ip"])
            body = {"window": wc["behavior_minutes"], "thresholds": {k: wc[k] for k in ("scan_min", "brute_min", "flood_min", "attack_min")},
                    "items": items}
            return self._send(200, json.dumps(body).encode(), "application/json", {"Cache-Control": "no-store"})
        if path == "/api/health":
            s = dict(ENGINE.stats)
            s.update(buckets=len(ENGINE.store.b), retention=CFG["retention"], bucket=CFG["bucket"],
                     now=int(time.time()), geo=GEOIP.status())
            return self._send(200, json.dumps(s).encode(), "application/json", {"Cache-Control": "no-store"})
        self._send(404, b"not found", "text/plain")


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def handle_error(self, request, client_address):
        # a browser or proxy closing or resetting a connection is routine: no traceback in the log
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def main():
    global ENGINE
    gc.set_threshold(50000, 20, 20)
    os.makedirs(os.path.dirname(CFG["state_file"]) or ".", exist_ok=True)
    ENGINE = Engine(CFG)
    stop = threading.Event()
    global ALERTS
    ALERTS = AlertManager(ALERT, ENGINE.store, ENGINE.watch, ENGINE.stats, ENGINE.ready, geo=GEOIP)
    th = threading.Thread(target=ENGINE.run, args=(stop,), daemon=True)
    th.start()
    threading.Thread(target=ALERTS.run, args=(stop,), daemon=True).start()
    if GEOIP.enabled:
        threading.Thread(target=GEOIP.run, args=(stop,), daemon=True).start()
    srv = Server(("0.0.0.0", PORT), Handler)

    def shutdown(*_):
        stop.set()
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print("geo: %s" % GEOIP.describe(), flush=True)
    print("dashboard listening on :%d  (access: %s | error: %s)" % (PORT, CFG["access_globs"], CFG["error_globs"]), flush=True)
    srv.serve_forever()
    th.join(timeout=10)


if __name__ == "__main__":
    main()
