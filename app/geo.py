import ipaddress
import json
import mmap
import os
import struct
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict, deque
from urllib.parse import quote

MARKER = b"\xab\xcd\xefMaxMind.com"
PRIVATE = ("", "Private network", "", "")


class MMDBError(Exception):
    pass


class MMDB:

    def __init__(self, path):
        with open(path, "rb") as fh:
            self.buf = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        i = self.buf.rfind(MARKER)
        if i < 0:
            raise MMDBError("not a MaxMind DB file")
        start = i + len(MARKER)
        meta, _ = self._decode(start, start)
        try:
            self.node_count = meta["node_count"]
            self.record_size = meta["record_size"]
            self.ip_version = meta["ip_version"]
        except (KeyError, TypeError):
            raise MMDBError("invalid metadata")
        if self.record_size not in (24, 28, 32) or self.ip_version not in (4, 6):
            raise MMDBError("unsupported database layout")
        self.meta = meta
        self.node_bytes = self.record_size // 4
        self.search_size = self.node_count * self.node_bytes
        self.data_start = self.search_size + 16
        self._v4_start = None

    def _record(self, node, bit):
        b = self.buf
        o = node * self.node_bytes
        rs = self.record_size
        if rs == 24:
            o += 3 * bit
            return int.from_bytes(b[o:o + 3], "big")
        if rs == 28:
            mid = b[o + 3]
            if bit == 0:
                return ((mid & 0xF0) << 20) | int.from_bytes(b[o:o + 3], "big")
            return ((mid & 0x0F) << 24) | int.from_bytes(b[o + 4:o + 7], "big")
        o += 4 * bit
        return int.from_bytes(b[o:o + 4], "big")

    def _ipv4_start(self):
        if self._v4_start is None:
            node = 0
            if self.ip_version == 6:
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._record(node, 0)
            self._v4_start = node
        return self._v4_start

    def get(self, ip):
        a = ipaddress.ip_address(ip)
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        if a.version == 6 and self.ip_version == 4:
            return None
        packed = a.packed
        node = self._ipv4_start() if a.version == 4 else 0
        nbits = len(packed) * 8
        for i in range(nbits):
            if node >= self.node_count:
                break
            node = self._record(node, (packed[i >> 3] >> (7 - (i & 7))) & 1)
        if node == self.node_count:
            return None
        if node < self.node_count:
            raise MMDBError("corrupt search tree")
        off = node - self.node_count + self.search_size
        rec, _ = self._decode(off, self.data_start)
        return rec if isinstance(rec, dict) else None

    def _decode(self, off, base):
        buf = self.buf
        ctrl = buf[off]
        off += 1
        t = ctrl >> 5
        if t == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                p = (vvv << 8) | buf[off]
                off += 1
            elif ss == 1:
                p = ((vvv << 16) | int.from_bytes(buf[off:off + 2], "big")) + 2048
                off += 2
            elif ss == 2:
                p = ((vvv << 24) | int.from_bytes(buf[off:off + 3], "big")) + 526336
                off += 3
            else:
                p = int.from_bytes(buf[off:off + 4], "big")
                off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if t == 0:  # extended type
            t = 7 + buf[off]
            off += 1
        size = ctrl & 31
        if size == 29:
            size = 29 + buf[off]
            off += 1
        elif size == 30:
            size = 285 + int.from_bytes(buf[off:off + 2], "big")
            off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(buf[off:off + 3], "big")
            off += 3
        if t == 7:  # map
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if t == 11:  # array
            out = []
            for _ in range(size):
                v, off = self._decode(off, base)
                out.append(v)
            return out, off
        if t == 14:  # boolean: the value is stored in the size field
            return bool(size), off
        raw = buf[off:off + size]
        off += size
        if t == 2:
            return raw.decode("utf-8", "replace"), off
        if t == 3:
            return struct.unpack(">d", raw)[0], off
        if t == 15:
            return struct.unpack(">f", raw)[0], off
        if t == 4:
            return bytes(raw), off
        if t in (5, 6, 9, 10):
            return int.from_bytes(raw, "big"), off
        if t == 8:
            return int.from_bytes(raw, "big", signed=(size == 4)), off
        raise MMDBError("unsupported data type %d" % t)


def _norm(rec):
    if not rec:
        return None
    t = tuple(str(rec.get(k) or "")[:80] for k in ("country_code", "country", "asn", "as_name"))
    return t if any(t) else None


def _global(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return a if a.is_global else False


class Geo:
    def __init__(self, cfg, clock=time.time):
        self.cfg = cfg
        self.clock = clock
        self.provider = cfg["provider"]
        self.token = cfg["token"]
        self.db = None
        self.db_path = ""            # file the open database was read from
        self.db_time = 0
        self._error = ""
        self.failures = 0            # api: consecutive failed requests
        self.dirty = False           # api cache changed since the last save
        self.lock = threading.Lock()
        self.cache = OrderedDict()   # api: ip -> (expires, tuple|None)
        self.queue = deque()
        self.queued = set()
        self.fatal = False
        self.wake = threading.Event()

    @property
    def enabled(self):
        return self.provider in ("mmdb", "api")

    def describe(self):
        if not self.enabled:
            return "geolocation disabled"
        if self.provider == "api":
            return "provider api, endpoint %s, token %s" % (self.cfg["api_url"], "set" if self.token else "missing")
        return "provider mmdb, database %s%s" % (self.cfg["data_db"], "" if os.path.isfile(self.cfg["data_db"]) else " (will be downloaded)")

    def status(self):
        with self.lock:
            return {"provider": self.provider, "ready": self.ready(),
                    "state": "ok" if self.ready() else "error" if self.error else "loading",
                    "source": "database" if self.provider == "mmdb" else "api", "db_updated": int(self.db_time), "pending": len(self.queue), "cached": len(self.cache)}

    @property
    def error(self):
        return self._error

    @error.setter
    def error(self, msg):
        if msg and msg != self._error:
            print("geo: %s" % msg, file=sys.stderr, flush=True)
        self._error = msg

    def ready(self):
        if self.provider == "mmdb":
            return self.db is not None
        return self.provider == "api" and not self.fatal and self.failures < 5

    def pending(self):
        return bool(self.queue)

    def lookup(self, ip):
        if not self.enabled:
            return None
        a = _global(ip)
        if a is None:
            return None
        if a is False:
            return PRIVATE
        if self.provider == "mmdb":
            db = self.db
            if db is None:
                return None
            try:
                return _norm(db.get(ip))
            except (MMDBError, IndexError, ValueError):
                return None
        now = self.clock()
        with self.lock:
            hit = self.cache.get(ip)
            if hit and hit[0] > now:
                self.cache.move_to_end(ip)
                return hit[1]
            if not self.fatal and ip not in self.queued and len(self.queue) < self.cfg["queue_max"]:
                self.queued.add(ip)
                self.queue.append(ip)
                self.wake.set()
        return hit[1] if hit else None

    def download_path(self):
        return self.cfg["data_db"]

    def find_db(self):
        return self.cfg["data_db"] if os.path.isfile(self.cfg["data_db"]) else ""

    def can_download(self):
        return bool(self.token)

    def load(self):
        path = self.find_db()
        if not path:
            return False
        try:
            db = MMDB(path)
            db.get("1.1.1.1")  # smoke test: walks the tree and decodes one record
        except (MMDBError, OSError, IndexError, ValueError, TypeError) as e:
            self.error = "database %s unreadable: %s" % (path, e)
            return False
        self.db, self.db_path, self.db_time, self.error = db, path, os.path.getmtime(path), ""
        return True

    def download(self):
        path = self.download_path()
        tmp = path + ".tmp"
        url = "%s?token=%s" % (self.cfg["db_url"], quote(self.token))
        req = urllib.request.Request(url, headers={"User-Agent": "treelog"})
        limit = 512 * 1048576
        try:
            with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as out:
                n = 0
                while True:
                    chunk = r.read(1048576)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > limit:
                        raise MMDBError("download too large")
                    out.write(chunk)
            MMDB(tmp).get("1.1.1.1")
            os.replace(tmp, path)
        except urllib.error.HTTPError as e:
            self.error = "database download failed: HTTP %d%s" % (e.code, " (check IPINFO_TOKEN)" if e.code in (401, 403) else "")
            return False
        except (urllib.error.URLError, OSError, MMDBError, IndexError, ValueError) as e:
            self.error = ("database download failed: %s" % e).replace(self.token, "***")[:200]
            return False
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return self.load()

    def _run_mmdb(self, stop):
        self.load()
        next_download = 0.0
        while not stop.is_set():
            now = self.clock()
            age = now - self.db_time if self.db else float("inf")
            if age > self.cfg["update_hours"] * 3600 and now >= next_download:
                if self.download():
                    print("geo database updated", flush=True)
                next_download = now + 900  # a failing provider is not polled every minute
            elif self.db is None:
                self.load()
            stop.wait(3600 if self.db else 60)  # retry sooner while there is no database

    def _fetch(self, ip):
        url = "%s/%s?token=%s" % (self.cfg["api_url"].rstrip("/"), ip, quote(self.token))
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "treelog"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return _norm(json.loads(r.read(65536)))

    def load_cache(self):
        path = self.cfg.get("cache_file")
        if not path:
            return
        try:
            with open(path) as fh:
                data = json.load(fh)
            now = self.clock()
            with self.lock:
                for ip, (exp, val) in data.items():
                    if exp > now and _global(ip) and len(val) == 4:
                        self.cache[ip] = (exp, tuple(str(x)[:80] for x in val))
        except (OSError, ValueError, TypeError):
            pass

    def save_cache(self):
        path = self.cfg.get("cache_file")
        if not path or not self.dirty:
            return
        with self.lock:
            data = {ip: [exp, list(val)] for ip, (exp, val) in self.cache.items() if val}
            self.dirty = False
        try:
            with open(path + ".tmp", "w") as fh:
                json.dump(data, fh, separators=(",", ":"))
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    def _store(self, ip, value, ttl):
        with self.lock:
            self.dirty = self.dirty or value is not None
            self.cache[ip] = (self.clock() + ttl, value)
            self.cache.move_to_end(ip)
            while len(self.cache) > self.cfg["cache_max"]:
                self.cache.popitem(last=False)

    def work_once(self):
        with self.lock:
            if not self.queue:
                return None
            ip = self.queue.popleft()
        try:
            value = self._fetch(ip)
            self._store(ip, value, 86400)
            self.error, self.failures = "", 0
        except urllib.error.HTTPError as e:
            self.failures += 1
            if e.code in (401, 403):
                self.fatal, self.error = True, "IPinfo API rejected the token (HTTP %d): check IPINFO_TOKEN" % e.code
            elif e.code == 429:
                self.error = "IPinfo API rate limit reached, backing off"
                with self.lock:
                    self.queue.appendleft(ip)
                return 60
            else:
                self._store(ip, None, 600)
                self.error = "IPinfo API error: HTTP %d" % e.code
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.failures += 1
            self._store(ip, None, 120)
            self.error = ("IPinfo API unreachable: %s" % e).replace(self.token, "***")[:200]
        with self.lock:
            self.queued.discard(ip)
        return 1.0 / max(0.1, self.cfg["api_rps"])

    def _run_api(self, stop):
        self.load_cache()
        last_save = self.clock()
        while not stop.is_set():
            if self.clock() - last_save > 300:
                self.save_cache()
                last_save = self.clock()
            if self.fatal:
                stop.wait(600)
                self.fatal = False   # allow a retry (the token may have been fixed at the proxy level)
                continue
            pause = self.work_once()
            if pause is None:
                self.wake.wait(5)
                self.wake.clear()
            else:
                stop.wait(pause)
        self.save_cache()

    def run(self, stop):
        if self.provider == "mmdb":
            self._run_mmdb(stop)
        elif self.provider == "api":
            self._run_api(stop)


def resolve_provider(cfg):
    p = cfg["provider"].strip().lower()
    if p == "auto":
        p = "api" if cfg["token"] else "off"
    if p not in ("off", "mmdb", "api"):
        print("unknown GEO_PROVIDER %r, geolocation disabled" % p, file=sys.stderr)
        p = "off"
    if p in ("api", "mmdb") and not cfg["token"]:
        print("GEO_PROVIDER=%s needs IPINFO_TOKEN, geolocation disabled" % p, file=sys.stderr)
        p = "off"
    return p
