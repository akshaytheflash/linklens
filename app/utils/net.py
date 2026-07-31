import socket
import ipaddress
from typing import List


def resolve_ips(hostname: str) -> List[str]:
    """Best-effort A/AAAA lookup, returns unique IPs."""
    ips: List[str] = []
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def is_private_ip(ip: str) -> bool:
    """True if the address is not publicly routable (or we can't tell)."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except Exception:
        return True


def is_private_host(hostname: str) -> bool:
    """True if ANY resolved address is private. Used to block SSRF-ish targets."""
    return any(is_private_ip(ip) for ip in resolve_ips(hostname))
