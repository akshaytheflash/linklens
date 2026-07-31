import re
from difflib import SequenceMatcher
from typing import Any, Dict
from urllib.parse import urlparse

# Well-known brands that phishing pages love to impersonate.
POPULAR_BRANDS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "netflix.com", "bankofamerica.com", "wellsfargo.com",
    "instagram.com", "linkedin.com", "whatsapp.com", "outlook.com", "icloud.com",
    "chase.com", "hsbc.com", "barclays.com", "stripe.com", "coinbase.com",
]

# Words that commonly appear in phishing / credential-harvesting URLs.
PHISHING_KEYWORDS = [
    "secure", "login", "verify", "bank", "update", "password", "signin",
    "account", "confirm", "suspended", "unlock", "billing", "wallet",
]

# TLDs that get handed out free/cheaply and are over-represented in spam.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "click",
    "link", "live", "rest", "online", "site", "icu", "zip", "mov",
}

# Classic URL shorteners. These are legitimate tools but a popular cover
# for hiding where a link really points.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "tiny.cc", "s.id",
    "v.gd", "lnkd.in", "rbx.st",
}

IPV4_REGEX = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def _domain_from_host(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return host


def _looks_like_hex_or_long(host: str) -> bool:
    # e.g. qw3rty4x6zz123.xyz — random alphanumeric hosts
    return bool(re.fullmatch(r"[a-z0-9]{10,}", host.split(".")[0], re.IGNORECASE))


def _brand_analysis(host: str) -> Dict[str, Any]:
    """Compare every label of the host against known brand names.

    "paypa1-secure-login.xyz" has a label ("paypa1") that's a near-miss of
    "paypal", and "paypal-update.tk" contains "paypal" outright — both are
    the classic phishing shapes that a whole-host comparison misses.
    """
    labels = [label for label in re.split(r"[.\-]", host.lower()) if label]
    best_brand = None
    best_ratio = 0.0
    exact_word = False

    for label in labels:
        for brand in POPULAR_BRANDS:
            brand_label = brand.split(".")[0]
            if label == brand_label:
                exact_word = True
            ratio = SequenceMatcher(None, label, brand_label).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_brand = brand

    is_actual_brand_domain = host.lower() in POPULAR_BRANDS or any(
        host.lower().endswith("." + brand) and host.lower().count(".") == brand.count(".") + 1
        for brand in POPULAR_BRANDS
    )

    return {
        "likely": (best_ratio >= 0.82 and best_brand and not is_actual_brand_domain) or (exact_word and not is_actual_brand_domain),
        "target": best_brand,
        "similarity": round(best_ratio, 3),
        "brandWordInHost": exact_word,
        "isActualBrandDomain": is_actual_brand_domain,
    }


def url_heuristics(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port

    lower_url = url.lower()
    lower_host = host.lower()

    # --- structural red flags ---
    ip_in_url = IPV4_REGEX.match(host or "") is not None
    at_symbol = "@" in url.split("//", 1)[-1]
    has_port = port is not None and port not in (80, 443)
    punycode = lower_host.startswith("xn--")
    double_slash = "//" in path

    subdomain_count = max(0, (host.count(".") - 1)) if host else 0
    many_subdomains = subdomain_count >= 3

    keyword_hits = [k for k in PHISHING_KEYWORDS if k in lower_url]

    brand = _brand_analysis(host)
    base = _domain_from_host(host) if host else ""

    shortener = base in URL_SHORTENERS

    tld = base.rsplit(".", 1)[-1] if "." in base else ""
    suspicious_tld = tld in SUSPICIOUS_TLDS

    long_path = len(path) > 200
    long_query = len(query) > 200

    hex_like_host = _looks_like_hex_or_long(host) if host else False

    return {
        "host": host,
        "path": path,
        "ipInUrl": ip_in_url,
        "atSymbolInUrl": at_symbol,
        "hasPort": has_port,
        "punycode": punycode,
        "doubleSlashInPath": double_slash,
        "subdomainCount": subdomain_count,
        "manySubdomains": many_subdomains,
        "phishingKeywords": keyword_hits,
        "typosquatting": {
            "likely": brand["likely"],
            "target": brand["target"],
            "similarity": brand["similarity"],
            "brandWordInHost": brand["brandWordInHost"],
            "isActualBrandDomain": brand["isActualBrandDomain"],
        },
        "urlShortener": shortener,
        "suspiciousTld": suspicious_tld,
        "tld": tld,
        "longPath": long_path,
        "longQuery": long_query,
        "hexLikeHost": hex_like_host,
    }
