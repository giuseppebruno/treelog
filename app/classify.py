import re
from urllib.parse import unquote

CATEGORIES = {
    "rce": "Command injection / RCE",
    "sqli": "SQL injection",
    "traversal": "Path traversal / LFI",
    "xss": "XSS",
    "probe": "Sensitive resource probing",
    "scanner": "Scanner user-agent",
    "malformed": "Malformed requests",
}

_PATTERNS = [
    ("rce", r"\$\{(?:jndi|\w+:-)|/bin/(?:ba)?sh\b|\bcmd(?:\.exe)?\s*/c\b|\b(?:wget|curl)\s+https?:"
            r"|base64_decode|\beval\s*\(|\b(?:system|exec|passthru|shell_exec)\s*\(|php://input"
            r"|allow_url_include|auto_prepend_file|\|\s*(?:sh|bash)\b|(?:[;|]|&&)\s*(?:cat|ls|id|uname|nc|whoami)(?:\s|$|[;|&])"
            r"|`[^`]+`|\$\([^)]+\)|\(\)\s*\{\s*:;\s*\}|#_memberAccess|\(#\w+=|/invokefunction|call_user_func"),
    ("sqli", r"union(?:\s|/\*.*?\*/|\+)+(?:all\s+)?select"
             r"|select\s+(?:distinct\s+)?[\w@`.()*']+(?:\s*,\s*[\w@`.()*']+)*\s+from\s+[\w`.]"
             r"|\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d"
             r"|'\s*(?:or|and)\s+['\"(\d]|'\s*(?:or|and)\s+\w+\s*(?:[=<>]|like\b)"
             r"|\bsleep\s*\(\s*\d|benchmark\s*\(|information_schema|waitfor\s+delay|pg_sleep"
             r"|extractvalue\s*\(|updatexml\s*\(|load_file\s*\(|into\s+(?:out|dump)file"
             r"|;\s*(?:drop|insert|update|delete)\s|/\*!\d*|\bgroup_concat\b|'\s*--"),
    ("traversal", r"\.\.[/\\]|\.\.;/|/etc/(?:passwd|shadow|hosts)\b|/proc/self|(?:c|d):[/\\]+(?:windows|winnt|boot)"
                  r"|\b(?:boot|win)\.ini\b|\b(?:php|file|expect|zip|phar|gopher|dict|ftp)://|/WEB-INF/|/META-INF/"),
    ("xss", r"<\s*/?\s*(?:script|iframe|img|svg|body|object|embed|link|style)\b|javascript\s*:"
            r"|\bon(?:error|load|click|mouseover|focus|toggle)\s*=|\balert\s*\(|document\.(?:cookie|location)"
            r"|String\.fromCharCode"),
    ("probe", r"/\.(?:env|git|svn|hg|aws|ssh|htaccess|htpasswd|ds_store|bash_history|npmrc|docker|idea|vscode)\b"
              r"|/(?:wp-login|xmlrpc|wp-config|wlwmanifest|wp-admin/(?:setup|install))[\w.-]*"
              r"|/(?:phpmyadmin|pma|myadmin|adminer|mysqladmin|phpinfo|server-status|server-info|jmx-console"
              r"|manager/html|actuator|cgi-bin|boaform|hnap1|vendor/phpunit|eval-stdin|solr/admin|jenkins|owa/auth)\b"
              r"|\b(?:backup|dump|database|db|vhost|www|wwwroot)\.(?:sql|zip|tar|gz|tgz|rar|7z)\b"
              r"|\.(?:sql|bak|swp|orig|pem|key)(?:$|\?)|\bconfig\.(?:php|ya?ml|ini|inc)\b|\bweb\.config\b"
              r"|composer\.(?:json|lock)|/(?:shell|c99|r57|wso|b374k|backdoor|webshell|cmd)\.php|\.(?:aspx?|jsp|cfm)(?:$|\?)"),
]
_ALL = re.compile("|".join("(?P<%s>%s)" % p for p in _PATTERNS), re.I)

_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|\bdirb\b|wfuzz|ffuf|feroxbuster|wpscan"
    r"|acunetix|netsparker|openvas|nessus|havij|zmeu|fimap|jaeles|burpcollaborator|censysinspect"
    r"|l9explore|l9tcpid|libwww-perl|internet-measurement", re.I)

_METHODS = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"}
_BAD_STATUS = {400, 408, 414, 431, 494, 495, 496, 497}
_NONPRINT = re.compile(r"[^\x20-\x7e]")


def _decode(s):
    try:
        return unquote(unquote(s))
    except Exception:
        return s


def clean_path(target):
    p = target.split("?", 1)[0]
    p = _NONPRINT.sub("?", p)
    return p if len(p) <= 70 else p[:70] + "…"


def classify(req, ua, status):
    parts = req.split(" ", 2)
    method = parts[0]
    if len(parts) < 2 or method not in _METHODS:
        if status in _BAD_STATUS or status == 444 or req in ("", "-") or "\\x" in req:
            return "malformed", "(non-HTTP request)"
        return None
    target = parts[1][:2000]
    s = _decode(target)
    m = _ALL.search(s)
    if m:
        return m.lastgroup, clean_path(target)
    if ua and ua != "-" and _SCANNER_UA.search(ua):
        return "scanner", clean_path(target)
    if status in _BAD_STATUS and (len(parts) < 3 or not parts[2].startswith("HTTP/")):
        return "malformed", clean_path(target)
    return None
