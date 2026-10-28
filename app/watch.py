import ipaddress
import re
import threading
from collections import deque

LOGIN_RE = re.compile(r"log[-_]?in|sign[-_]?in|xmlrpc\.php|/auth(?:enticate)?/?$|j_security_check|/administrator/?(?:index\.php)?$", re.I)

REQ, C5XX, ATK, BLOCKED, REDIRECT, EXPOSED, ERROR = range(7)


class Rec:
    __slots__ = ("first", "last", "req", "p4", "login", "c401", "atk", "c5", "vhost")

    def __init__(self, t, vhost):
        self.first = self.last = t
        self.req = self.login = self.c401 = self.atk = self.c5 = 0
        self.p4 = set()
        self.vhost = vhost


class Watch:
    def __init__(self, cfg):
        self.cfg = cfg
        self.keep = int(cfg["keep_minutes"])
        self.window = int(cfg["behavior_minutes"]) * 60
        self.max_ips = int(cfg["max_ips"])
        self.min = {}
        self.vmin = {}   # minute -> {vhost: [requests, 5xx, hostile]}
        self.events = deque(maxlen=500)
        self.ips = {}
        self.bad = set()
        self.lock = threading.Lock()

    def add(self, t, vhost, ip, method, target, code, hit):
        m = int(t // 60)
        v = self.min.get(m)
        if v is None:
            if len(self.min) > self.keep + 10:
                for k in [k for k in self.min if k < m - self.keep]:
                    del self.min[k]
                    self.vmin.pop(k, None)
            v = self.min[m] = [0] * 7
        vm = self.vmin.setdefault(m, {})
        if vhost not in vm and len(vm) >= 50:   # the name comes from the log: keep this bounded
            vhost_key = "(other vhosts)"
        else:
            vhost_key = vhost
        x = vm.get(vhost_key)
        if x is None:
            x = vm[vhost_key] = [0, 0, 0]
        x[0] += 1
        if code >= 500:
            x[1] += 1
        if hit:
            x[2] += 1
        v[REQ] += 1
        if code >= 500:
            v[C5XX] += 1
        if hit:
            v[ATK] += 1
            kind = None
            if code >= 500:
                v[ERROR] += 1
                kind = "error"
            elif code >= 400:
                v[BLOCKED] += 1
            elif code >= 300:
                v[REDIRECT] += 1
            else:
                v[EXPOSED] += 1
                kind = "exposed"
            if kind:
                self.events.append((t, kind, vhost, hit[0], hit[1], code, ip))
        self._behavior(t, vhost, ip, method, target, code, hit)

    def _behavior(self, t, vhost, ip, method, target, code, hit):
        r = self.ips.get(ip)
        if r is None or t - r.first > self.window:
            if r is None:
                if ip in self.bad:
                    return
                try:  # valid IPs only: the list may end up in blocking commands, never trust the log
                    ipaddress.ip_address(ip)
                except ValueError:
                    if len(self.bad) < 2000:
                        self.bad.add(ip)
                    return
                if len(self.ips) >= self.max_ips:
                    self._evict(t)
            r = self.ips[ip] = Rec(t, vhost)
        r.last = t
        r.vhost = vhost
        r.req += 1
        if 400 <= code < 500 and len(r.p4) < 256:
            r.p4.add(hash(target.split("?", 1)[0]))
        if method == "POST" and LOGIN_RE.search(target.split("?", 1)[0]):
            r.login += 1
        if code == 401:
            r.c401 += 1
        if hit:
            r.atk += 1
        if code >= 500:
            r.c5 += 1

    def _evict(self, t):
        old = [k for k, r in self.ips.items() if t - r.last > self.window]
        if not old:
            old = sorted(self.ips, key=lambda k: self.ips[k].last)[: max(1, len(self.ips) // 10)]
        for k in old:
            del self.ips[k]

    def window_totals(self, now, minutes):
        lo = int(now // 60) - minutes + 1
        tot = [0] * 7
        with self.lock:
            for m, v in self.min.items():
                if m >= lo:
                    for i in range(7):
                        tot[i] += v[i]
            ev = [e for e in self.events if e[0] >= now - minutes * 60]
        return tot, ev

    def window_vhosts(self, now, minutes):
        lo = int(now // 60) - minutes + 1
        out = {}
        with self.lock:
            for m, d in self.vmin.items():
                if m >= lo:
                    for name, x in d.items():
                        o = out.setdefault(name, [0, 0, 0])
                        for i in range(3):
                            o[i] += x[i]
        return out

    def offenders(self, now, limit=100):
        c = self.cfg
        out = []
        with self.lock:
            for ip, r in self.ips.items():
                if now - r.last > self.window:
                    continue
                reasons = []
                if len(r.p4) >= c["scan_min"]:
                    reasons.append("scan")
                if r.login >= c["brute_min"] or r.c401 >= c["brute_min"]:
                    reasons.append("brute")
                if r.req >= c["flood_min"]:
                    reasons.append("flood")
                if r.atk >= c["attack_min"]:
                    reasons.append("attacks")
                if reasons:
                    try:
                        a = ipaddress.ip_address(ip)
                        private = a.is_private or a.is_loopback or a.is_link_local
                    except ValueError:
                        continue
                    out.append({"ip": ip, "reasons": reasons, "req": r.req, "p4": len(r.p4), "login": r.login,
                                "c401": r.c401, "atk": r.atk, "c5": r.c5, "last": int(r.last),
                                "vhost": r.vhost, "private": private})
        out.sort(key=lambda o: (-len(o["reasons"]), -o["req"]))
        return out[:limit]
