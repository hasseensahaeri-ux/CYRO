"""Request protection: CSRF token, rate limiting, SSRF guard."""
import hmac
import ipaddress
import secrets
import socket
import time
from collections import defaultdict, deque
from functools import wraps

from flask import jsonify, request, session

import config

_hits = defaultdict(deque)


class BlockedHost(Exception):
    """Host resolves to a non-public address."""


class ResolveError(Exception):
    """Host could not be resolved."""


def api_error(code, status=400):
    return jsonify({"ok": False, "error": code}), status


def protected(fn):
    """CSRF (for POST) + per-IP rate limit for API endpoints."""
    @wraps(fn)
    def wrapper(*a, **kw):
        if request.method == "POST":
            sent = request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                return api_error("csrf", 403)
        now = time.time()
        q = _hits[request.remote_addr]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= config.RATE_LIMIT_PER_MIN:
            return api_error("rate_limit", 429)
        q.append(now)
        return fn(*a, **kw)
    return wrapper


def _blocked_ip(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped:
        ip = mapped
    return (not ip.is_global) or ip.is_multicast


def resolve_public(host, port=443):
    """Return public IPs for host or raise BlockedHost / ResolveError."""
    h = host.lower().rstrip(".")
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".corp")):
        raise BlockedHost(h)
    try:
        ipaddress.ip_address(h)
        if _blocked_ip(h):
            raise BlockedHost(h)
        return [h]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise ResolveError(h)
    ips = sorted({i[4][0] for i in infos})
    if not ips or any(_blocked_ip(ip) for ip in ips):
        raise BlockedHost(h)
    return ips
