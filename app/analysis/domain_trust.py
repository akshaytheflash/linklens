import datetime
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import whois

from app.utils.net import is_private_ip, resolve_ips

# WHOIS lookups hit public servers and can hang, so run them in a worker
# thread with a hard timeout. Also cache per-host to avoid repeat queries.
_whois_cache: Dict[str, Optional[Dict[str, Any]]] = {}
_whois_lock = threading.Lock()
_whois_executor = ThreadPoolExecutor(max_workers=2)


def _get_cert(hostname: str, port: int = 443) -> Optional[dict]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except Exception:
        return None


def _fetch_whois(hostname: str) -> Dict[str, Any]:
    try:
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0] if created else None
        if isinstance(created, datetime.datetime):
            age = (datetime.datetime.now(datetime.timezone.utc) - created.astimezone(datetime.timezone.utc)).days
        else:
            age = None
        registrar = getattr(w, "registrar", None) or None
        return {
            "ageDays": age,
            "created": created.isoformat() if isinstance(created, datetime.datetime) else None,
            "registrar": registrar,
        }
    except Exception:
        return {"ageDays": None, "created": None, "registrar": None}


def _get_whois(hostname: str) -> Dict[str, Any]:
    key = hostname.lower()
    with _whois_lock:
        if key in _whois_cache:
            return _whois_cache[key]
    try:
        data = _whois_executor.submit(_fetch_whois, key).result(timeout=6)
    except (TimeoutError, Exception):
        data = {"ageDays": None, "created": None, "registrar": None}
    with _whois_lock:
        _whois_cache[key] = data
    return data


def _cert_summary(cert: dict, host: str) -> Dict[str, Any]:
    names: list[str] = []
    try:
        for t in cert.get("subject", []):
            for key, val in t:
                if key == "commonName":
                    names.append(val)
        for t in cert.get("subjectAltName", []):
            if t[0] == "DNS":
                names.append(t[1])
    except Exception:
        pass

    issuer = ""
    try:
        parts = []
        for t in cert.get("issuer", []):
            for key, val in t:
                if key == "organizationName":
                    parts.append(val)
        issuer = ", ".join(parts)
    except Exception:
        pass

    not_after = cert.get("notAfter", "")
    expires_in_days = None
    try:
        expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
        expires_in_days = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
    except Exception:
        pass

    mismatch = True
    for n in names:
        if n.startswith("*.") and host.lower().endswith(n[2:].lower()):
            mismatch = False
            break
        if n.lower() == host.lower():
            mismatch = False
            break

    return {
        "names": sorted(set(names)),
        "issuer": issuer,
        "expiresInDays": expires_in_days,
        "mismatch": mismatch,
    }


def domain_trust(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_https = parsed.scheme.lower() == "https"

    data: Dict[str, Any] = {
        "host": host,
        "https": is_https,
        "whois": {"ageDays": None, "created": None, "registrar": None},
        "certificate": {"valid": False, "names": [], "issuer": "", "expiresInDays": None, "mismatch": None},
        "dns": {"ips": [], "privateIp": None},
    }

    if host:
        ips = resolve_ips(host)
        data["dns"]["ips"] = ips
        data["dns"]["privateIp"] = any(is_private_ip(ip) for ip in ips)
        data["whois"] = _get_whois(host)

    if is_https and host:
        cert = _get_cert(host)
        if cert:
            summary = _cert_summary(cert, host)
            summary["valid"] = True
            data["certificate"] = summary

    return data
