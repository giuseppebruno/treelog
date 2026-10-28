import hashlib
import hmac
import json
import sys
import threading
import time
import urllib.request
from collections import Counter, deque
from urllib.parse import urlsplit

from watch import ATK, C5XX, ERROR, REQ

SEVERITY = {"critical": ("CRITICAL", 5, "rotating_light"), "warning": ("WARNING", 4, "warning"),
            "info": ("INFO", 3, "information_source"), "resolved": ("RESOLVED", 3, "white_check_mark"),
            "test": ("TEST", 3, "bell")}
REASONS = {"scan": "enumeration (many distinct 404s)", "brute": "credential brute force",
           "flood": "request flood", "attacks": "repeated attacks"}


def _post(url, body, headers, timeout=10):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "treelog", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        r.read(1024)
        return r.status


def send_ntfy(cfg, p):
    u = urlsplit(cfg["ntfy_url"])
    body = {"topic": u.path.strip("/"), "title": p["title"], "message": p["message"],
            "priority": SEVERITY[p["severity"]][1], "tags": [SEVERITY[p["severity"]][2]]}
    if cfg["dashboard_url"]:
        body["click"] = cfg["dashboard_url"]
    h = {"Authorization": "Bearer " + cfg["ntfy_token"]} if cfg["ntfy_token"] else {}
    _post("%s://%s/" % (u.scheme, u.netloc), json.dumps(body).encode(), h)


def send_telegram(cfg, p):
    text = "[%s] %s\n%s" % (SEVERITY[p["severity"]][0], p["title"], p["message"])
    if cfg["dashboard_url"]:
        text += "\n" + cfg["dashboard_url"]
    url = "%s/bot%s/sendMessage" % (cfg["telegram_api"].rstrip("/"), cfg["telegram_token"])
    # no parse_mode: the text contains attacker-controlled paths
    _post(url, json.dumps({"chat_id": cfg["telegram_chat_id"], "text": text,
                           "disable_web_page_preview": True}).encode(), {})


def send_webhook(cfg, p):
    body = json.dumps(p, separators=(",", ":")).encode()
    h = {}
    if cfg["webhook_secret"]:
        h["X-Treelog-Signature"] = "sha256=" + hmac.new(cfg["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    _post(cfg["webhook_url"], body, h)


class AlertManager:
    def __init__(self, cfg, store, watch, stats, ready, clock=time.time, geo=None):
        self.cfg, self.store, self.watch, self.stats, self.ready, self.clock = cfg, store, watch, stats, ready, clock
        self.geo = geo
        self.W = int(cfg["window_minutes"])
        self.rules = set(cfg["rules"])
        self.state = {}  # rule -> {"active", "last_sent", "clear"}
        self.history = deque(maxlen=50)
        self.lock = threading.Lock()
        self.senders = {}
        if cfg["ntfy_url"]:
            self.senders["ntfy"] = send_ntfy
        if cfg["telegram_token"] and cfg["telegram_chat_id"]:
            self.senders["telegram"] = send_telegram
        if cfg["webhook_url"]:
            self.senders["webhook"] = send_webhook
        self._base = (0, 0)
        self._offenders_seen = {}

    def _baseline(self, now):
        if now - self._base[0] < 300:
            return self._base[1]
        W = self.W * 60
        hi = now - W
        lo = hi - 86400
        attacks = covered = 0
        s = self.store
        with s.lock:
            for t, d in s.b.items():
                if lo <= t < hi - s.B:
                    covered += s.B
                    for b in d.values():
                        attacks += sum(b.atk.values())
        val = attacks / (covered / W) if covered >= 3 * 3600 else None
        self._base = (now, val)
        return val

    @staticmethod
    def _top(events, n=5):
        c = Counter((e[2], e[4], e[5]) for e in events)
        return "; ".join("%s%s (%s) x%d" % (s + " " if s != "(default)" else "", p, code, k)
                         for (s, p, code), k in c.most_common(n))

    @staticmethod
    def _hosts(counts, n=4):
        items = [(k, v) for k, v in counts.most_common() if v]
        if not items or all(k == "(default)" for k, _ in items):
            return ""
        out = ", ".join("%s (%d)" % kv for kv in items[:n])
        return out + (" +%d more" % (len(items) - n) if len(items) > n else "")

    def _detail(self, events):
        lines = []
        hosts = self._hosts(Counter(e[2] for e in events))
        if hosts:
            lines.append("Virtual hosts: " + hosts)
        lines.append("Top: " + self._top(events))
        src = Counter(e[6] for e in events)
        lines.append("Sources: " + ", ".join("%s%s (%d)" % (ip, self._where(ip), k) for ip, k in src.most_common(3)))
        return "\n" + "\n".join(lines)

    def conditions(self, now):
        c, W = self.cfg, self.W
        tot, ev = self.watch.window_totals(now, W)
        out = {}
        if "server_errors" in self.rules:
            n = tot[ERROR]
            sel = [e for e in ev if e[1] == "error"]
            out["server_errors"] = (n >= c["attack_5xx_min"], "critical", "5xx under attack",
                                    "%d hostile requests received 5xx in the last %d min (%d%% of hostile requests)."
                                    % (n, W, 100 * n // max(1, tot[ATK])) + self._detail(sel))
        if "exposed" in self.rules:
            cats = set(c["exposed_categories"])
            sel = [e for e in ev if e[1] == "exposed" and e[3] in cats]
            out["exposed"] = (len(sel) >= c["exposed_min"], "warning", "High-risk hostile requests served 2xx",
                              "%d requests (%s) were served 2xx in the last %d min."
                              % (len(sel), ", ".join(sorted({e[3] for e in sel})), W) + self._detail(sel))
        if "error_rate" in self.rules:
            req, c5 = tot[REQ], tot[C5XX]
            hosts = self._hosts(Counter({k: v[1] for k, v in self.watch.window_vhosts(now, W).items()}))
            out["error_rate"] = (req >= c["min_requests"] and c5 / max(1, req) >= c["error_rate"], "critical",
                                 "Elevated 5xx error rate",
                                 "%d 5xx responses out of %d requests in the last %d min (%.1f%%)." % (c5, req, W, 100 * c5 / max(1, req))
                                 + ("\nVirtual hosts: " + hosts if hosts else ""))
        if "spike" in self.rules:
            base = self._baseline(now)
            atk = tot[ATK]
            active = base is not None and atk >= c["spike_min"] and atk >= c["spike_factor"] * max(base, 1)
            hosts = self._hosts(Counter({k: v[2] for k, v in self.watch.window_vhosts(now, W).items()}))
            out["spike"] = (active, "warning", "Hostile traffic spike",
                            "%d hostile requests in the last %d min, %.1fx the previous 24 h average (%.0f)."
                            % (atk, W, atk / max(base or 1, 1), base or 0) + ("\nVirtual hosts: " + hosts if hosts else ""))
        if "silence" in self.rules and c["silence_minutes"] > 0:
            last = self.stats.get("last_event", 0)
            mins = int((now - last) // 60)
            out["silence"] = (last > 0 and mins >= c["silence_minutes"], "critical", "No log activity",
                              "No new access log lines for %d minutes." % mins)
        return out

    def evaluate(self, now=None):
        now = now or self.clock()
        sent = []
        for rule, (active, sev, title, msg) in self.conditions(now).items():
            st = self.state.setdefault(rule, {"active": False, "last_sent": 0, "clear": 0})
            if active:
                st["clear"] = 0
                if not st["active"] or now - st["last_sent"] >= self.cfg["cooldown_minutes"] * 60:
                    st["active"], st["last_sent"] = True, now
                    sent.append(self.notify("alert", rule, sev, title, msg, now))
            elif st["active"]:
                st["clear"] += 1
                if st["clear"] >= 2:  # hysteresis: two consecutive evaluations without the condition
                    st["active"] = False
                    if self.cfg["notify_resolved"]:
                        sent.append(self.notify("resolved", rule, "resolved", "Resolved: " + title,
                                                "The condition is no longer active.", now))
        if "offenders" in self.rules:
            sent += self._offenders(now)
        return [s for s in sent if s]

    def _where(self, ip):
        g = self.geo.lookup(ip) if self.geo else None
        if not g or not (g[0] or g[2]):
            return ""
        return " [%s]" % ", ".join(x for x in (g[0], (g[2] + " " + g[3]).strip()) if x)

    def _offenders(self, now):
        fresh = []
        for o in self.watch.offenders(now):
            if o["private"] or now - self._offenders_seen.get(o["ip"], 0) < 6 * 3600:
                continue
            fresh.append(o)
        if not fresh:
            return []
        for o in fresh:
            self._offenders_seen[o["ip"]] = now
        if len(self._offenders_seen) > 5000:
            self._offenders_seen = {k: v for k, v in self._offenders_seen.items() if now - v < 6 * 3600}
        lines = ["%s%s: %s (%d requests%s)" % (o["ip"], self._where(o["ip"]), ", ".join(REASONS[r] for r in o["reasons"]), o["req"],
                                              "" if o["vhost"] == "(default)" else " on " + o["vhost"])
                 for o in fresh[:10]]
        more = "" if len(fresh) <= 10 else " (+%d)" % (len(fresh) - 10)
        return [self.notify("alert", "offenders", "info", "New offending IPs%s" % more, "\n".join(lines), now)]

    def notify(self, event, rule, severity, title, message, now=None):
        p = {"source": "treelog", "name": self.cfg["name"], "event": event, "rule": rule, "severity": severity,
             "title": "%s: %s" % (self.cfg["name"], title) if self.cfg["name"] else title,
             "message": message[:1500], "timestamp": int(now or self.clock())}
        p["text"] = p["content"] = "[%s] %s - %s" % (SEVERITY[severity][0], p["title"], p["message"])  # convenient for chat-style webhooks
        delivery = {}
        for name, fn in self.senders.items():
            err = None
            for attempt in (0, 1):
                try:
                    fn(self.cfg, p)
                    err = None
                    break
                except Exception as ex:
                    err = ex
                    if attempt == 0 and self.clock is time.time:
                        time.sleep(1)
            delivery[name] = "ok" if err is None else "error: %s" % str(err)[:120]
            if err is not None:
                print("alert %s not delivered: %s" % (name, err), file=sys.stderr)
        rec = {"t": p["timestamp"], "event": event, "rule": rule, "severity": severity,
               "title": p["title"], "message": p["message"], "delivery": delivery}
        if event != "test":   # test notifications are reported to the caller only
            with self.lock:
                self.history.appendleft(rec)
        return rec

    def send_test(self):
        return self.notify("test", "test", "test", "Test notification",
                           "If you can read this, the channel is configured correctly.")

    def status(self):
        with self.lock:
            hist = list(self.history)
        c = self.cfg
        return {"channels": sorted(self.senders), "rules": sorted(self.rules), "window": self.W,
                "cooldown": c["cooldown_minutes"], "history": hist}

    def run(self, stop):
        self.ready.wait()
        while not stop.is_set():
            try:
                self.evaluate()
            except Exception as e:
                print("alert evaluation failed: %s" % e, file=sys.stderr)
            stop.wait(self.cfg["eval_seconds"])
