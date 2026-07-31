from typing import Any, Dict, List

import requests

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# Security headers that, when missing, tell us the site's authors don't
# care much about hardening — mildly interesting but not damning on its own.
SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def perform_static_prefetch(
    url: str, user_agent: str = DEFAULT_USER_AGENT
) -> Dict[str, Any]:
    """Lightweight preflight: follows redirects and pulls headers so we have
    something to compare against even if the headless browser fails later.

    Tries HEAD first (cheap), falls back to a small GET if the server
    rejects HEAD requests.
    """
    result: Dict[str, Any] = {
        "originalUrl": url,
        "finalUrl": None,
        "redirectChain": [],
        "headers": {},
        "status": None,
        "securityHeaders": [],
        "missingSecurityHeaders": [],
        "error": None,
    }

    def _run(method: str) -> Dict[str, Any]:
        resp = requests.request(
            method,
            url,
            allow_redirects=True,
            timeout=12,
            headers={"User-Agent": user_agent},
            stream=True,
        )
        resp.close()
        chain: List[str] = [r.url for r in resp.history] + [resp.url]
        return {
            "redirectChain": chain,
            "finalUrl": resp.url,
            "headers": dict(resp.headers),
            "status": resp.status_code,
        }

    try:
        data = _run("HEAD")
    except Exception as head_err:
        try:
            data = _run("GET")
        except Exception as get_err:
            result["error"] = f"HEAD failed ({head_err}); GET failed ({get_err})"
            return result

    result.update(data)

    present = []
    missing = []
    for header in SECURITY_HEADERS:
        key = next((k for k in result["headers"] if k.lower() == header), None)
        if key:
            present.append(SECURITY_HEADERS[header])
        else:
            missing.append(SECURITY_HEADERS[header])
    result["securityHeaders"] = present
    result["missingSecurityHeaders"] = missing

    return result
