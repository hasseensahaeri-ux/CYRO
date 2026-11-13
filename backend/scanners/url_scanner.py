"""URL analysis. Rule-based scoring; never fetches page content."""
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import parse_qs, urlsplit

import config
from .. import security
from ..messages import build, verdict


class ScanError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "facebook", "instagram", "netflix",
          "whatsapp", "binance", "alrajhi", "snapchat", "twitter", "linkedin", "dhl", "fedex",
          "aramex", "absher", "icloud", "outlook"]
SUSP_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support",
             "country", "kim", "loan", "men", "icu", "buzz", "rest", "cyou", "cfd", "sbs", "monster"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy",
              "shorturl.at", "tiny.cc", "buff.ly"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password",
            "wallet", "banking", "billing", "suspend", "unlock"]
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
IPLIKE_RE = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$")

_bl_cache = {"mtime": None, "set": frozenset()}


def blocklist():
    p = config.BLOCKLIST_PATH
    try:
        m = p.stat().st_mtime
    except OSError:
        return frozenset()
    if _bl_cache["mtime"] != m:
        items = set()
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                items.add(line.split()[-1])
        _bl_cache.update(mtime=m, set=frozenset(items))
    return _bl_cache["set"]


def _registrable(host):
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:]), labels[-3], labels[:-3]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[-2], labels[:-2]
    return host, host, []


def parse(raw):
    """Validate and normalise. Returns (parts, host, ascii_host, assumed)."""
    raw = (raw or "").strip()
    if not raw:
        raise ScanError("empty")
    if len(raw) > config.MAX_URL_CHARS:
        raise ScanError("too_long")
    if any(c.isspace() or ord(c) < 32 for c in raw):
        raise ScanError("invalid_url")
    assumed = "://" not in raw
    if assumed:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        parts.port  # validates port range
    except ValueError:
        raise ScanError("invalid_url")
    if parts.scheme not in ("http", "https") or not host:
        raise ScanError("invalid_url")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ScanError("invalid_url")
    is_ip = False
    try:
        ipaddress.ip_address(ascii_host)
        is_ip = True
    except ValueError:
        if not (HOST_RE.match(ascii_host) or IPLIKE_RE.match(ascii_host)) or len(ascii_host) > 253:
            raise ScanError("invalid_url")
    return parts, host, ascii_host, assumed, is_ip or bool(IPLIKE_RE.match(ascii_host))


def _tls_check(host, ip):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=config.TLS_TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert = t.getpeercert()
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
        return build("cert_ok", 0, sev="ok", issuer=issuer, days=days)
    except ssl.SSLCertVerificationError as e:
        return build("cert_invalid", 30, reason=(e.verify_message or "verification failed"))
    except (OSError, ssl.SSLError):
        return build("tls_unreachable", 0)


def analyze(raw, network=True):
    parts, host, ahost, assumed, is_ip = parse(raw)
    findings = []
    add = lambda code, pts, **p: findings.append(build(code, pts, **p))
    https = parts.scheme == "https"
    if assumed:
        add("assumed_scheme", 0)
    if not https:
        add("no_https", 15)
    if is_ip:
        add("ip_host", 25)
    if "@" in parts.netloc:
        add("at_sign", 20)
    if host != ahost or "xn--" in ahost:
        add("punycode", 20)
    reg, name, subs = _registrable(ahost) if not is_ip else (ahost, ahost, [])
    if len(subs) >= 3:
        add("many_subdomains", 10, n=len(subs))
    full = parts.geturl()
    if len(full) > 100:
        add("long_url", 8, n=len(full))
    if len(ahost) > 40:
        add("long_host", 8)
    if ahost.count("-") >= 3:
        add("many_hyphens", 8)
    tld = ahost.rsplit(".", 1)[-1]
    if not is_ip and tld in SUSP_TLDS:
        add("susp_tld", 12, tld=tld)
    if not is_ip:
        segs = [s for lbl in [name] + subs for s in lbl.split("-")]
        for b in BRANDS:
            direct = name != b and any(s == b or s.startswith(b) for s in segs)
            leet = any(b in s.translate(LEET) and b not in s for s in segs)
            if direct:
                add("brand_abuse", 25, brand=b, reg=reg)
                break
            if leet:
                add("brand_leet", 25, brand=b)
                break
    if ahost in SHORTENERS:
        add("shortener", 10)
    low = (parts.path + "?" + parts.query).lower() + "." + ahost
    hits = [k for k in KEYWORDS if k in low]
    if hits:
        add("keywords", min(15, 5 * len(hits)), items=", ".join(hits[:4]))
    if parts.port not in (None, 80, 443):
        add("odd_port", 10, port=parts.port)
    if any(re.match(r"https?://", v, re.I) for vals in parse_qs(parts.query).values() for v in vals):
        add("redirect_param", 8)

    bl = blocklist()
    parents = {".".join(ahost.split(".")[i:]) for i in range(len(ahost.split(".")) - 1)} | {ahost}
    if parents & bl:
        add("blocklisted", 80)

    meta = {"dns_checked": False, "tls_checked": False, "blocklist_size": len(bl)}
    if network:
        try:
            ips = security.resolve_public(ahost)
            meta["dns_checked"] = True
            if https and parts.port in (None, 443):
                meta["tls_checked"] = True
                findings.append(_tls_check(ahost, ips[0]))
        except security.BlockedHost:
            raise ScanError("internal_blocked")
        except security.ResolveError:
            add("dns_fail", 10)

    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    clean = parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]).geturl()
    return {"url": clean[:300], "host": ahost, "https": https, "score": score,
            "verdict": verdict(score), "findings": findings, "meta": meta}
