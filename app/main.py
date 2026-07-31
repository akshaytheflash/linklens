import asyncio
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import idna
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for

from app.ai.gemini_client import GeminiClient
from app.analysis.domain_trust import domain_trust
from app.analysis.dynamic_analyzer import perform_dynamic_analysis
from app.analysis.html_parse import parse_html_overview
from app.analysis.static_fetch import perform_static_prefetch
from app.analysis.url_heuristics import url_heuristics
from app.analysis.yara_scanner import YaraScanner
from app.config import AppConfig
from app.observability.logging import assign_request_id, setup_json_logging
from app.scoring.verdict import compute_verdict
from app.utils.net import is_private_host, resolve_ips
from app.utils.rate_limit import RateLimiter

load_dotenv()

app = Flask(__name__)
config = AppConfig.from_env()

logger = setup_json_logging(sample_rate=config.log_sample_rate)
rate_limiter = RateLimiter(config.rate_limit_requests, config.rate_limit_window_seconds)

yara_rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "yararules")
yara_scanner = YaraScanner(rules_directory=yara_rules_dir)

gemini = GeminiClient(api_key=config.gemini_api_key, model=config.gemini_model)

DEFAULT_TIMEOUT = config.analysis_timeout_seconds

os.makedirs(config.screenshots_dir, exist_ok=True)

SCAN_TTL_SECONDS = 30 * 60
_scan_store: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_scan_store_lock = Lock()


def _store_result(result: Dict[str, Any]) -> str:
    scan_id = uuid.uuid4().hex
    with _scan_store_lock:
        _purge_stale_results()
        _scan_store[scan_id] = (time.time(), result)
    return scan_id


def _load_result(scan_id: str) -> Optional[Dict[str, Any]]:
    with _scan_store_lock:
        entry = _scan_store.get(scan_id)
        if not entry:
            return None
        created_at, result = entry
        if time.time() - created_at > SCAN_TTL_SECONDS:
            _scan_store.pop(scan_id, None)
            return None
        return result


def _purge_stale_results() -> None:
    now = time.time()
    for scan_id, (created_at, _) in list(_scan_store.items()):
        if now - created_at > SCAN_TTL_SECONDS:
            _scan_store.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Score helpers — each returns (0..10 score, list of human notes).
# ---------------------------------------------------------------------------
def _score_url(heur: Dict[str, Any]) -> Tuple[float, list]:
    score = 0.0
    notes = []
    if heur.get("ipInUrl"):
        score += 8
        notes.append("URL uses a raw IP address instead of a domain")
    if heur.get("atSymbolInUrl"):
        score += 7
        notes.append("'@' in URL can hide the real destination")
    if heur.get("punycode"):
        score += 5
        notes.append("Punycode (homograph) domain")
    if heur.get("urlShortener"):
        score += 5
        notes.append("URL shortener — destination is hidden")
    if heur.get("hasPort"):
        score += 2
        notes.append("Non-standard port in URL")
    if heur.get("doubleSlashInPath"):
        score += 3
        notes.append("Double-slash obfuscation in path")
    if heur.get("suspiciousTld"):
        score += 3
        notes.append(f"Cheap/free TLD: .{heur.get('tld')}")
    if heur.get("manySubdomains"):
        score += 4
        notes.append(f"Unusual number of subdomains ({heur.get('subdomainCount')})")
    if heur.get("longPath"):
        score += 2
        notes.append("Very long URL path")
    if heur.get("longQuery"):
        score += 1
        notes.append("Very long query string")
    if heur.get("hexLikeHost"):
        score += 2
        notes.append("Random-looking hostname")
    keywords = heur.get("phishingKeywords", [])
    if keywords:
        score += min(len(keywords) * 2, 6)
        notes.append(f"Phishing-ish words in URL: {', '.join(keywords)}")
    return min(score, 10.0), notes


def _score_brand(heur: Dict[str, Any]) -> Tuple[float, list]:
    typo = heur.get("typosquatting", {})
    score = 0.0
    notes = []
    if typo.get("likely"):
        target = typo.get("target")
        similarity = typo.get("similarity", 0)
        score += 8
        if typo.get("brandWordInHost"):
            notes.append(f"URL host contains the brand '{target}' but isn't the real site")
        else:
            notes.append(f"Host closely resembles {target} ({similarity * 100:.0f}% similar)")
    elif typo.get("brandWordInHost") and not typo.get("isActualBrandDomain"):
        score += 4
        notes.append(f"Brand word '{typo.get('target')}' embedded in a lookalike host")
    return min(score, 10.0), notes


def _score_redirect(static: Dict[str, Any], dynamic: Dict[str, Any]) -> Tuple[float, list]:
    chain = dynamic.get("redirectChain") or static.get("redirectChain") or []
    score = 0.0
    notes = []
    if len(chain) > 1:
        hops = len(chain) - 1
        score += min(hops * 1.5, 6)
        notes.append(f"{hops} redirect hop(s) before the page loaded")
    if len(chain) > 3:
        score += 2
        notes.append("Long multi-stage redirect chain")
    # Cross-domain redirects are the interesting bit.
    hosts = set()
    for hop in chain:
        try:
            hosts.add(hop.split("//", 1)[-1].split("/", 1)[0])
        except Exception:
            pass
    if len(hosts) > 1:
        score += 3
        notes.append("Redirect chain crosses between different domains")
    return min(score, 10.0), notes


def _score_content(overview: Dict[str, Any], html_yara: list, credential_exfil: list) -> Tuple[float, list]:
    score = 0.0
    notes = []
    if html_yara:
        score += 8
        notes.append(f"YARA rules flagged page content ({len(html_yara)} rule(s))")
    # Static parse and dynamic capture both look for password fields that
    # submit somewhere else; treat them as one signal, not two.
    if credential_exfil or overview.get("passwordForms"):
        score += 8
        count = max(len(credential_exfil), len(overview.get("passwordForms") or []))
        notes.append(f"{count} password form(s) submit to a different domain")
    if overview.get("externalBaseTag"):
        score += 4
        notes.append("<base> tag rewrites relative links to another site")
    if overview.get("metaRefresh"):
        score += 3
        notes.append("Page uses a meta-refresh redirect")
    if overview.get("iframes", {}).get("hidden", 0) > 0:
        score += 3
        notes.append("Hidden iframes present (possible cloaked content)")
    if overview.get("suspiciousScripts"):
        score += 3
        notes.append(f"{len(overview['suspiciousScripts'])} obfuscated inline script(s) found")
    if len(overview.get("crossSiteResources", {}).get("forms", [])) > 0:
        score += 2
        notes.append("Forms submit to external domains")
    if overview.get("interactionLocks", {}).get("rightClickDisabled"):
        score += 1
        notes.append("Right-click disabled (blocks inspection)")
    return min(score, 10.0), notes


def _score_ai(link, content, popups) -> Tuple[float, list]:
    scores = [link.get("riskScore", 0), content.get("riskScore", 0), popups.get("riskScore", 0)]
    avg = sum(scores) / len(scores)
    notes = []
    if link.get("riskScore", 0) >= 5:
        notes.append(f"AI: link structure looks risky ({link['riskScore']:.1f}/10)")
    if content.get("riskScore", 0) >= 5:
        notes.append(f"AI: page content looks like social engineering ({content['riskScore']:.1f}/10)")
    if popups.get("riskScore", 0) >= 5:
        notes.append(f"AI: popups/dialogs look like scams ({popups['riskScore']:.1f}/10)")
    return round(avg, 2), notes


def _score_network(dynamic: Dict[str, Any], url_heur: Dict[str, Any]) -> Tuple[float, list]:
    indicators = dynamic.get("networkIndicators", {}).get("indicators", [])
    score = 0.0
    notes = []
    if "ip-tracking-request" in indicators:
        score += 6
        notes.append("Page called an IP-tracking service")
    if "cross-origin-password-form" in indicators:
        # Already scored under Page Content; note it here for completeness.
        notes.append("Password form posts to another origin")
    suspicious_posts = dynamic.get("thirdParty", {}).get("suspiciousPosts", [])
    if suspicious_posts:
        score += 6
        reasons = {p.get("reason") for p in suspicious_posts}
        notes.append(f"Suspicious POST data ({', '.join(sorted(reasons))})")
    if "content-disposition-attachment" in indicators:
        score += 5
        notes.append("Server tried to force a file download")
    if "suspicious-extension" in indicators:
        score += 4
        notes.append("Suspicious file extension requested")
    if dynamic.get("networkStats", {}).get("failed", 0) >= 5:
        score += 2
        notes.append("Many failed network requests")
    return min(score, 10.0), notes


def _score_downloads(downloads: list) -> Tuple[float, list]:
    if not downloads:
        return 0.0, []
    score = 0.0
    notes = []
    any_yara = False
    for item in downloads:
        if item.get("yaraMatches"):
            any_yara = True
            notes.append(f"Download '{item.get('filename')}' matched YARA: {', '.join(item['yaraMatches'])}")
    if any_yara:
        score += 9
    else:
        score += 4
        notes.append("Files were downloaded during load (but YARA found nothing)")
    return min(score, 10.0), notes


def _score_domain(trust: Dict[str, Any], url_heur: Dict[str, Any]) -> Tuple[float, list]:
    score = 0.0
    notes = []
    age = trust.get("whois", {}).get("ageDays")
    if age is not None:
        if age < 30:
            score += 7
            notes.append(f"Domain is only {age} days old")
        elif age < 180:
            score += 4
            notes.append(f"Domain is fairly new ({age} days)")
    else:
        score += 1
        notes.append("WHOIS age unavailable")
    if not trust.get("https"):
        score += 4
        notes.append("Site is served over plain HTTP")
    cert = trust.get("certificate", {})
    if cert.get("mismatch"):
        score += 5
        notes.append("SSL certificate doesn't match the domain")
    if cert.get("expiresInDays") is not None and cert.get("expiresInDays") < 14:
        score += 2
        notes.append("SSL certificate expiring soon")
    if url_heur.get("ipInUrl") and trust.get("dns", {}).get("privateIp"):
        score += 9
        notes.append("URL points to a private/loopback IP")
    return min(score, 10.0), notes


def _score_behavior(dynamic: Dict[str, Any], ai_popups: Dict[str, Any]) -> Tuple[float, list]:
    score = 0.0
    notes = []
    dialogs = dynamic.get("popups", {}).get("dialogs", [])
    modals = dynamic.get("popups", {}).get("modals", [])
    count = len(dialogs) + len(modals)
    if count:
        score += min(count * 2, 6)
        notes.append(f"{count} popup(s)/overlay(s) appeared during load")
    if ai_popups.get("riskScore", 0) >= 5:
        score += 3
        notes.append("AI flagged popup content as a scam")
    if dynamic.get("antiBot", {}).get("blocked"):
        score += 5
        notes.append("Site served a bot-check/captcha to the scanner")
    if dynamic.get("consoleMessages"):
        errors = sum(1 for m in dynamic["consoleMessages"] if m.get("type") == "error")
        if errors >= 3:
            score += 2
            notes.append(f"{errors} JavaScript console errors")
    if dynamic.get("pageErrors"):
        score += 1
        notes.append("Page threw uncaught JavaScript errors")
    return min(score, 10.0), notes


# ---------------------------------------------------------------------------
# Core analysis pipeline
# ---------------------------------------------------------------------------
def run_analysis(url: str, timeout_seconds: int) -> Dict[str, Any]:
    t0 = time.time()
    warnings: list = []

    url_heur = url_heuristics(url)

    static_result = perform_static_prefetch(url)

    t1 = time.time()
    dynamic_result = asyncio.run(
        perform_dynamic_analysis(
            url=url,
            timeout_seconds=timeout_seconds,
            screenshots_dir=config.screenshots_dir,
        )
    )
    t2 = time.time()

    final_url = dynamic_result.get("finalUrl") or static_result.get("finalUrl") or url
    final_host = _host_of(final_url)

    # DNS sanity checks: warn if the resolved IPs changed between the static
    # preflight and the browser load (possible DNS rebinding / fast flux).
    initial_host = _host_of(url)
    initial_ips = set(resolve_ips(initial_host))
    final_ips = set(resolve_ips(final_host))
    if initial_ips and final_ips and initial_ips != final_ips:
        warnings.append("dns_ips_changed")

    if config.block_punycode and (initial_host.lower().startswith("xn--") or final_host.lower().startswith("xn--")):
        warnings.append("punycode_domain")

    html_overview = parse_html_overview(dynamic_result.get("finalHtml", ""), final_url)
    html_yara = yara_scanner.scan_content(dynamic_result.get("finalHtml", ""))

    downloads = dynamic_result.get("downloads", [])
    for item in downloads:
        path = item.get("path")
        if path:
            item["yaraMatches"] = yara_scanner.scan_file(path)

    trust = domain_trust(final_url)

    # AI calls run in parallel to shave a few seconds off the scan.
    with ThreadPoolExecutor(max_workers=3) as pool:
        link_fut = pool.submit(gemini.evaluate_link, url, final_url, html_overview.get("title", ""))
        content_fut = pool.submit(gemini.evaluate_content, html_overview.get("textSnippet", ""))
        popup_texts = dynamic_result.get("popups", {}).get("dialogs", []) + [
            m.get("text", "") for m in dynamic_result.get("popups", {}).get("modals", [])
        ]
        popup_fut = pool.submit(gemini.evaluate_popups, popup_texts)
        ai_link = link_fut.result(timeout=20)
        ai_content = content_fut.result(timeout=20)
        ai_popups = popup_fut.result(timeout=20)

    credential_exfil = dynamic_result.get("credentialExfil", {}).get("crossOriginPasswordForms", [])

    categories = {}
    for key, scorer, args in (
        ("url", _score_url, (url_heur,)),
        ("brand", _score_brand, (url_heur,)),
        ("redirect", _score_redirect, (static_result, dynamic_result)),
        ("content", _score_content, (html_overview, html_yara, credential_exfil)),
        ("ai", _score_ai, (ai_link, ai_content, ai_popups)),
        ("network", _score_network, (dynamic_result, url_heur)),
        ("downloads", _score_downloads, (downloads,)),
        ("domain", _score_domain, (trust, url_heur)),
        ("behavior", _score_behavior, (dynamic_result, ai_popups)),
    ):
        score, notes = scorer(*args)
        categories[key] = {"score": score, "notes": notes}

    verdict = compute_verdict(categories, ai_disabled=not gemini.enabled)

    response = {
        "overallVerdict": verdict["verdict"],
        "overallScore": verdict["overallScore"],
        "scoreBreakdown": verdict["breakdown"],
        "reasons": verdict["reasons"],
        "ai": {"enabled": gemini.enabled, "link": ai_link, "content": ai_content, "popups": ai_popups},
        "aiJudgement": {"link": ai_link, "content": ai_content},
        "urlHeuristics": url_heur,
        "static": static_result,
        "redirectChain": dynamic_result.get("redirectChain", []),
        "finalUrl": final_url,
        "screenshots": dynamic_result.get("screenshots", []),
        "html": html_overview,
        "htmlYara": html_yara,
        "network": dynamic_result.get("networkIndicators", {}),
        "networkStats": dynamic_result.get("networkStats", {}),
        "thirdParty": dynamic_result.get("thirdParty", {}),
        "popups": dynamic_result.get("popups", {}),
        "downloads": downloads,
        "domainTrust": trust,
        "antiBot": dynamic_result.get("antiBot", {}),
        "fingerprinting": dynamic_result.get("fingerprinting", {}),
        "consoleMessages": dynamic_result.get("consoleMessages", []),
        "pageErrors": dynamic_result.get("pageErrors", []),
        "credentialExfil": dynamic_result.get("credentialExfil", {}),
        "loadMetrics": dynamic_result.get("loadMetrics"),
        "warnings": warnings,
        "dynamicError": dynamic_result.get("error"),
        "trace": {
            "static_ms": int((t1 - t0) * 1000),
            "dynamic_ms": int((t2 - t1) * 1000),
            "total_ms": int((time.time() - t0) * 1000),
        },
    }
    return response


# ---------------------------------------------------------------------------
# Validation / guards
# ---------------------------------------------------------------------------
def _host_of(url: str) -> str:
    """Netloc without the port (also handles IPv6 literals)."""
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return url.split("//", 1)[-1].split("/", 1)[0]


def _validate_and_guard(url: Optional[str]) -> Optional[Dict[str, Any]]:
    if not url or not url.lower().startswith(("http://", "https://")):
        return {"error": "Enter a valid URL starting with http:// or https://"}
    if len(url) > config.max_url_length:
        return {"error": f"URL too long (max {config.max_url_length} characters)"}
    host = _host_of(url)
    try:
        idna.encode(host)
    except Exception:
        return {"error": "Invalid characters in URL"}
    if config.block_punycode and host.lower().startswith("xn--"):
        return {"error": "Punycode (homograph) domains are blocked"}
    if not config.allow_private_ips and is_private_host(host):
        return {"error": "URL resolves to a private/loopback address and is blocked"}
    return None


def _domain_policy(host: str) -> Optional[str]:
    host = host.lower()
    if config.deny_domains and any(host == d or host.endswith("." + d) for d in config.deny_domains):
        return "Domain is on the deny list"
    if config.allow_domains and not any(host == a or host.endswith("." + a) for a in config.allow_domains):
        return "Domain is not on the allow list"
    return None


# ---------------------------------------------------------------------------
# Web layer
# ---------------------------------------------------------------------------
@app.before_request
def _assign_request_id_and_rate_limit():
    assign_request_id()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if not rate_limiter.allow(ip):
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "rate_limited"}), 429
        return render_template("index.html", error="Rate limit exceeded. Please wait a moment and try again."), 429


@app.after_request
def _set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; font-src 'self'"
    )
    return resp


@app.get("/")
def index():
    response = render_template("index.html")
    return app.response_class(
        response=response,
        status=200,
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "linklens", "yara_rules": yara_scanner.get_rule_count(), "ai_enabled": gemini.enabled})


def _extract_timeout(value: Any) -> int:
    try:
        parsed = int(value)
        return max(10, min(parsed, 90))
    except Exception:
        return DEFAULT_TIMEOUT


@app.post("/scan")
def scan_form():
    url = (request.form.get("url") or "").strip()
    timeout_seconds = _extract_timeout(request.form.get("timeoutSeconds", DEFAULT_TIMEOUT))

    guard = _validate_and_guard(url)
    if guard:
        return render_template("index.html", error=guard["error"]), 400

    host = _host_of(url)
    policy = _domain_policy(host)
    if policy:
        return render_template("index.html", error=policy), 403

    result = run_analysis(url, timeout_seconds)
    logger.info("scan_form_complete", extra={"verdict": result["overallVerdict"]})
    scan_id = _store_result(result)
    return redirect(url_for("scan_result", scan_id=scan_id), code=303)


@app.get("/result/<scan_id>")
def scan_result(scan_id: str):
    result = _load_result(scan_id)
    if result is None:
        return redirect(url_for("index"))
    html = render_template("result.html", result=result)
    return app.response_class(
        response=html,
        status=200,
        mimetype="text/html",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/analyze")
def analyze_url():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url")
    url = url.strip() if isinstance(url, str) else ""

    guard = _validate_and_guard(url)
    if guard:
        return jsonify(guard), 400

    host = _host_of(url)
    policy = _domain_policy(host)
    if policy:
        return jsonify({"error": policy}), 403

    timeout_seconds = _extract_timeout(payload.get("timeoutSeconds", DEFAULT_TIMEOUT))

    result = run_analysis(url, timeout_seconds)
    logger.info("analyze_complete", extra={"verdict": result["overallVerdict"]})
    return app.response_class(
        response=json.dumps(result, ensure_ascii=False),
        status=200,
        mimetype="application/json",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
