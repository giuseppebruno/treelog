import calendar
import glob
import gzip
import json
import os
import re
import sys
import threading
import time

from classify import classify, clean_path, _NONPRINT
from watch import Watch

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

DEFAULT_ACCESS_RE = (
    r'^(?:(?P<vhost>\S+:\d+) )?(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) \S+'
    r'(?: "(?:[^"\\]|\\.)*" "(?P<ua>(?:[^"\\]|\\.)*)")?')
NGX_ERR = re.compile(r'^(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):\d\d \[(\w+)\] \d+#\d+: (?:\*\d+ )?(.*)$')
APA_ERR = re.compile(r'^\[(?:\w{3} )?(\w{3}) (\d\d?) (\d\d):(\d\d):\d\d(?:\.\d+)? (\d{4})\] '
                     r'\[(?:[\w.]+:)?(\w+)\] (?:\[pid [^\]]+\] )?(?:\[client [^\]]+\] )?(.*)$')
_Q = re.compile(r'"[^"]*"')
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_PATH = re.compile(r"(: )/\S+")
_NUM = re.compile(r"(?<![A-Za-z0-9])\d+")
LEVELS = {"warning": "warn", "error": "error", "crit": "crit", "alert": "alert", "emerg": "emerg",
          "notice": "notice", "info": "info", "debug": "debug", "warn": "warn"}


def norm_msg(m):
    m = m.split(", client:")[0]
    m = _Q.sub('"…"', m)
    m = _IP.sub("<ip>", m)
    m = _PATH.sub(r"\1<path>", m)
    return _NUM.sub("N", m)[:110]


_SRV = re.compile(r"server: ([^,\s]+)")
_GENERIC_DIRS = {"", "logs", "log", "nginx", "apache", "apache2", "httpd", "www", "var", "mnt"}
_LOGNAME = re.compile(r"^(.*?)\.log(?:[-._]?\d+)?(?:\.gz)?$", re.I)
_ROLE = re.compile(r"[._-]*(?:access|error)[._-]*", re.I)


def clean_vhost(s):
    s = _NONPRINT.sub("?", s.strip().lower())[:80]
    return s or "(default)"


def outcome(code):
    if code >= 500:
        return "error"
    if code >= 400:
        return "blocked"
    if code >= 300:
        return "redirect"
    return "exposed"


class Bucket:
    __slots__ = ("tot", "atk", "ips", "err", "e5")

    def __init__(self):
        self.tot, self.atk, self.ips, self.err, self.e5 = {}, {}, {}, {}, {}


def _bump(d, key, cap, overflow):
    if key in d:
        d[key] += 1
    elif len(d) < cap:
        d[key] = 1
    else:
        d[overflow] = d.get(overflow, 0) + 1


class Store:
    OTHER = "(other vhosts)"

    def __init__(self, bucket, retention, cap, max_vhosts=50):
        self.B, self.R, self.cap, self.max_vhosts = bucket, retention, cap, max_vhosts
        self.b = {}  # t -> {vhost: Bucket}
        self.vhosts = set()
        self.lock = threading.Lock()
        self.dirty = False

    def vhost(self, name):
        if name in self.vhosts:
            return name
        if len(self.vhosts) < self.max_vhosts:
            self.vhosts.add(name)
            return name
        return self.OTHER

    def _bk(self, t, vhost):
        k = int(t // self.B) * self.B
        d = self.b.get(k)
        if d is None:
            d = self.b[k] = {}
        b = d.get(vhost)
        if b is None:
            b = d[vhost] = Bucket()
        return b

    def access(self, t, vhost, code, atk, path, ip):
        b = self._bk(t, self.vhost(vhost))
        c = str(code) if 100 <= code <= 599 else "0"
        b.tot[c] = b.tot.get(c, 0) + 1
        cap = self.cap
        if atk:
            sys_intern = sys.intern
            _bump(b.atk, (atk, c, sys_intern(path)), cap, (atk, c, "(other)"))
            _bump(b.ips, (sys_intern(ip), atk, c), cap * 3 // 4, ("(other)", atk, c))
        elif code >= 500:
            _bump(b.e5, (sys.intern(path), c), cap // 5, ("(other)", c))

    def error(self, t, vhost, level, msg):
        _bump(self._bk(t, self.vhost(vhost)).err, (level, msg), self.cap // 3, (level, "(other)"))

    def prune(self, now):
        lo = now - self.R
        for k in [k for k in self.b if k + self.B < lo]:
            del self.b[k]
        self.vhosts = {s for d in self.b.values() for s in d}

    def dump(self):
        out = {}
        for k, d in self.b.items():
            out[k] = {vhost: {"tot": b.tot, "atk": [[*a, n] for a, n in b.atk.items()],
                             "ips": [[*a, n] for a, n in b.ips.items()],
                             "err": [[*a, n] for a, n in b.err.items()],
                             "e5": [[*a, n] for a, n in b.e5.items()]} for vhost, b in d.items()}
        return out

    def load(self, data):
        for k, d in data.items():
            if "tot" in d:  # state from the previous version (no virtual hosts)
                d = {"(default)": d}
            out = self.b.setdefault(int(k), {})
            for vhost, v in d.items():
                b = Bucket()
                b.tot = v["tot"]
                b.atk = {(r[0], r[1], sys.intern(r[2])): r[3] for r in v["atk"]}
                b.ips = {(sys.intern(r[0]), r[1], r[2]): r[3] for r in v["ips"]}
                b.err = {(r[0], r[1]): r[2] for r in v["err"]}
                b.e5 = {(sys.intern(r[0]), r[1]): r[2] for r in v["e5"]}
                out[vhost] = b
                self.vhosts.add(vhost)

    def snapshot(self, window, top, vhost=None, points=96):
        now = time.time()
        B = self.B
        lo = int((now - window) // B) * B
        nb = max(1, int((now - lo) // B) + 1)
        step = max(1, -(-nb // points))
        S = B * step
        series = {}
        tot, atk, ips, err, e5 = {}, {}, {}, {}, {}
        per_vhost = {}  # vhost -> [requests, denied, redirected, 2xx, 5xx]
        order = ("blocked", "redirect", "exposed", "error")
        with self.lock:
            for t, d in self.b.items():
                if t < lo:
                    continue
                for sname, b in d.items():
                    ps = per_vhost.setdefault(sname, [0, 0, 0, 0, 0])
                    ps[0] += sum(b.tot.values())
                    for (cat, c, _p), n in b.atk.items():
                        ps[1 + order.index(outcome(int(c)))] += n
                    if vhost is not None and sname != vhost:
                        continue
                    for c, n in b.tot.items():
                        tot[c] = tot.get(c, 0) + n
                    for d_src, d_dst in ((b.atk, atk), (b.ips, ips), (b.err, err), (b.e5, e5)):
                        for k, n in d_src.items():
                            kk = (sname, *k)  # the virtual host is the first field of every row
                            d_dst[kk] = d_dst.get(kk, 0) + n
                    row = series.setdefault(int(t // S) * S, [0] * 8)
                    for c, n in b.tot.items():
                        code = int(c)
                        row[0 if code < 300 else 1 if code < 400 else 2 if code < 500 else 3] += n
                    for (cat, c, _p), n in b.atk.items():
                        row[4 + order.index(outcome(int(c)))] += n
        s0 = int(lo // S) * S
        ser = []
        t = s0
        while t <= now:
            ser.append([t] + series.get(t, [0] * 8))
            t += S

        def top_rows(d, leaf):
            # rows beyond the limit are folded into "(other)" (field `leaf`) instead of dropped, so totals stay exact
            items = sorted(d.items(), key=lambda kv: -kv[1])
            out = dict(items[:top])
            for k, n in items[top:]:
                k2 = k[:leaf] + ("(other)",) + k[leaf + 1:]
                out[k2] = out.get(k2, 0) + n
            return [[*k, n] for k, n in sorted(out.items(), key=lambda kv: -kv[1])]

        def top_ips(d):
            # limit distinct addresses, not rows: an address keeps all its rows (host, class, status) or none,
            # so country and network views stay meaningful; the rest is grouped under "(other)"
            per = {}
            for k, n in d.items():
                per[k[1]] = per.get(k[1], 0) + n
            keep = set(sorted(per, key=per.get, reverse=True)[:top])
            out = {}
            for k, n in d.items():
                k2 = k if k[1] in keep else k[:1] + ("(other)",) + k[2:]
                out[k2] = out.get(k2, 0) + n
            return [[*k, n] for k, n in sorted(out.items(), key=lambda kv: -kv[1])]

        vhosts = sorted(([k, *v] for k, v in per_vhost.items()), key=lambda r: -r[1])
        return {"now": int(now), "window": window, "bucket": S, "vhost": vhost, "vhosts": vhosts,
                "tot": tot, "series": ser,
                # rows: atk [vhost, cat, status, path, n] · ips [vhost, ip, cat, status, n]
                #       err [vhost, level, msg, n] · e5 [vhost, path, status, n]
                "atk": top_rows(atk, 3), "ips": top_ips(ips), "err": top_rows(err, 2), "e5": top_rows(e5, 1),
                "ips_unique": len({k[1] for k in ips if k[1] != "(other)"})}


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = Store(cfg["bucket"], cfg["retention"], cfg["cap"], cfg["max_vhosts"])
        self.vhost_re = re.compile(cfg["vhost_regex"]) if cfg["vhost_regex"] else None
        self._vhosts = {}
        self.watch = Watch(cfg["watch"])
        self.watch.lock = self.store.lock
        self.ready = threading.Event()  # set after the first scan: alert evaluation starts from there
        self._recent_lo = 0
        self.access_re = re.compile(cfg["access_regex"] or DEFAULT_ACCESS_RE)
        self.ignore = re.compile(cfg["ignore_regex"], re.I) if cfg["ignore_regex"] else None
        self.ignore_ips = set(cfg["ignore_ips"])
        self.files = {}  # "dev:ino" -> {"off": int, "seen": float}
        self.initialized = False
        self._sample = ""
        self._warned_nofiles = False
        self._warned_bad = 10
        self.stats = {"ok": 0, "bad": 0, "err_ok": 0, "err_bad": 0, "files": 0, "last_event": 0, "started": time.time(),
                      "indexing": True, "files_done": 0, "bytes_total": 0, "bytes_done": 0}
        self._minute = {}
        self._load()

    def _ts(self, ts):
        key = ts[:17] + ts[21:26]
        base = self._minute.get(key)
        if base is None:
            tz = ts[21:26]
            off = (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60) * (-1 if tz[0] == "-" else 1)
            base = calendar.timegm((int(ts[7:11]), MONTHS[ts[3:6]], int(ts[0:2]),
                                    int(ts[12:14]), int(ts[15:17]), 0)) - off
            if len(self._minute) > 4000:
                self._minute.clear()
            self._minute[key] = base
        return base + int(ts[18:20])

    def _access_line(self, line, now_lo, vhost):
        m = self.access_re.match(line)
        if not m:
            self.stats["bad"] += 1
            self._sample = self._sample or line[:200]
            return
        g = m.groupdict()
        try:
            t = self._ts(g["ts"])
        except Exception:
            self.stats["bad"] += 1
            return
        self.stats["ok"] += 1
        if t < now_lo:
            return
        ip, req, code = g["ip"], g["req"], int(g["status"])
        ua = g.get("ua") or ""
        if ip in self.ignore_ips or (self.ignore and self.ignore.search(req)):
            return
        vh = g.get("vhost")
        if vh:
            vhost = clean_vhost(vh.rsplit(":", 1)[0])
        hit = classify(req, ua, code)
        if hit:
            path = hit[1]
            self.store.access(t, vhost, code, hit[0], path, ip)
        elif code >= 500:
            tgt = req.split(" ", 2)
            self.store.access(t, vhost, code, None, clean_path(tgt[1]) if len(tgt) > 1 else "-", ip)
        else:
            self.store.access(t, vhost, code, None, "", ip)
        if t > self.stats["last_event"]:
            self.stats["last_event"] = t
        if t >= self._recent_lo:
            tg = req.split(" ", 2)
            self.watch.add(t, vhost, ip, tg[0], tg[1] if len(tg) > 1 else "", code, hit)

    def _error_line(self, line, now_lo, vhost):
        if line[:1] == "[":
            m = APA_ERR.match(line)
            if m:
                mon, d, hh, mm, y, lvl, msg = m.groups()
                t = time.mktime((int(y), MONTHS.get(mon, 1), int(d), int(hh), int(mm), 0, 0, 0, -1))
        else:
            m = NGX_ERR.match(line)
            if m:
                y, mo, d, hh, mm, lvl, msg = m.groups()
                t = time.mktime((int(y), int(mo), int(d), int(hh), int(mm), 0, 0, 0, -1))
        if not m:
            self.stats["err_bad"] += 1
            return
        self.stats["err_ok"] += 1
        if t >= now_lo:
            sv = _SRV.search(msg) if vhost == "(default)" else None
            if sv:  # single shared error log: nginx reports the request's server_name
                vhost = clean_vhost(sv.group(1))
            self.store.error(t, vhost, LEVELS.get(lvl.lower(), lvl.lower()), norm_msg(msg))

    def _process(self, lines, kind, vhost):
        now_lo = time.time() - self.cfg["retention"]
        fn = self._access_line if kind == "access" else self._error_line
        self._recent_lo = time.time() - self.cfg["watch"]["span"]
        with self.store.lock:
            for ln in lines:
                if ln:
                    fn(ln.decode("utf-8", "replace") if isinstance(ln, bytes) else ln, now_lo, vhost)
            self.store.prune(time.time())
            self.store.dirty = True

    def _vhost_of(self, path):
        vhost = self._vhosts.get(path)
        if vhost is not None:
            return vhost
        if self.vhost_re:
            m = self.vhost_re.search(path)
            vhost = clean_vhost(m.group("vhost") if m and "vhost" in m.groupdict() else m.group(1)) if m else "(default)"
        else:
            name = os.path.basename(path)
            m = _LOGNAME.match(name)
            base = _ROLE.sub("", m.group(1) if m else os.path.splitext(name)[0])
            if base:
                vhost = clean_vhost(base)
            else:
                parent = os.path.basename(os.path.dirname(path))
                vhost = "(default)" if parent.lower() in _GENERIC_DIRS else clean_vhost(parent)
        self._vhosts[path] = vhost
        return vhost

    def _plan(self):
        out = []
        for kind, patterns in (("access", self.cfg["access_globs"]), ("error", self.cfg["error_globs"])):
            paths = sorted({p for pat in patterns for p in glob.glob(pat, recursive=True)})
            for path in paths:
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if os.path.isfile(path):
                    out.append((kind, path, st))
        return out

    def _pending(self, path, st, first):
        f = self.files.get("%s:%s" % (st.st_dev, st.st_ino))
        if path.endswith(".gz"):
            return st.st_size if (f is None and first) else 0
        off = max(0, st.st_size - self.cfg["backfill_mb"] * 1048576) if f is None else min(f["off"], st.st_size)
        return st.st_size - off

    def scan(self):
        first = not self.initialized
        seen_keys = set()
        plan = self._plan()
        if self.stats["indexing"]:  # only on the first pass after startup
            self.stats["bytes_total"] = sum(self._pending(p, st, first) for _, p, st in plan)
            self.stats["bytes_done"] = self.stats["files_done"] = 0
            self.stats["files"] = len(plan)
        for kind, path, st in plan:
            key = "%s:%s" % (st.st_dev, st.st_ino)
            seen_keys.add(key)
            try:
                self._read(path, key, st, kind, first)
            except Exception as e:  # an unreadable file must not stop the others
                print("read error %s: %s" % (path, e), file=sys.stderr)
            if self.stats["indexing"]:
                self.stats["files_done"] += 1
        self.stats["files"] = len(plan)
        if plan:
            self.initialized = True
        elif not self._warned_nofiles:
            print("warning: no log files found: check the volume mounted on /logs and ACCESS_LOGS / ERROR_LOGS", flush=True)
        self._warned_nofiles = not plan
        if self.stats["bad"] >= self._warned_bad:
            print("warning: %d access lines could not be parsed (check the log format or ACCESS_REGEX), e.g.: %s"
                  % (self.stats["bad"], self._sample), flush=True)
            self._warned_bad = self.stats["bad"] * 10
        cutoff = time.time() - 7 * 86400
        for k in [k for k, v in self.files.items() if k not in seen_keys and v["seen"] < cutoff]:
            del self.files[k]

    def _read(self, path, key, st, kind, first):
        f = self.files.get(key)
        maxb = self.cfg["backfill_mb"] * 1048576
        if path.endswith(".gz"):
            if f is None:
                self.files[key] = {"off": st.st_size, "seen": time.time()}
                if first:  # .gz files are read only on first run (otherwise they would be duplicates)
                    with gzip.open(path, "rb") as fh:
                        self._process(fh, kind, self._vhost_of(path))
                    self.stats["bytes_done"] += st.st_size
            else:
                f["seen"] = time.time()
            return
        if f is None:
            f = self.files[key] = {"off": max(0, st.st_size - maxb), "seen": 0}
            skip_partial = f["off"] > 0
        else:
            skip_partial = False
        f["seen"] = time.time()
        if st.st_size < f["off"]:  # truncated / copytruncate
            f["off"] = 0
        if st.st_size == f["off"]:
            return
        with open(path, "rb") as fh:
            fh.seek(f["off"])
            while True:
                chunk = fh.read(4 * 1048576)
                if not chunk:
                    break
                cut = chunk.rfind(b"\n")
                if cut < 0:
                    if len(chunk) < 4 * 1048576:
                        break  # incomplete line: retry on the next pass
                    cut = len(chunk) - 1
                lines = chunk[:cut].split(b"\n")
                if skip_partial:
                    lines = lines[1:]
                    skip_partial = False
                self._process(lines, kind, self._vhost_of(path))
                f["off"] += cut + 1
                self.stats["bytes_done"] += cut + 1
                fh.seek(f["off"])

    def _load(self):
        p = self.cfg["state_file"]
        try:
            with open(p) as fh:
                d = json.load(fh)
            self.files = d["files"]
            self.initialized = d.get("init", True)
            self.store.load(d["buckets"])
            self.stats["ok"] = d.get("ok", 0)
            self.stats["err_ok"] = d.get("eok", 0)
            print("state restored: %d buckets" % len(self.store.b), flush=True)
        except FileNotFoundError:
            pass
        except Exception as e:
            print("state unreadable (%s), starting from scratch" % e, file=sys.stderr)
            self.files, self.initialized = {}, False
            self.store.b.clear()

    def save(self, force=False):
        if not (self.store.dirty or force):
            return
        p = self.cfg["state_file"]
        with self.store.lock:
            data = {"v": 1, "init": self.initialized, "files": self.files, "ok": self.stats["ok"], "eok": self.stats["err_ok"],
                    "buckets": self.store.dump()}
            self.store.dirty = False
        try:
            tmp = p + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(data, fh, separators=(",", ":"))
            os.replace(tmp, p)
        except OSError as e:
            print("state save failed: %s" % e, file=sys.stderr)

    def run(self, stop):
        last_save = time.time()
        while not stop.is_set():
            try:
                self.scan()
            except Exception as e:
                print("scan failed: %s" % e, file=sys.stderr)
            self.stats["indexing"] = False
            self.ready.set()
            if time.time() - last_save > self.cfg["save_every"]:
                self.save()
                last_save = time.time()
            stop.wait(self.cfg["poll"])
        self.save(force=True)
