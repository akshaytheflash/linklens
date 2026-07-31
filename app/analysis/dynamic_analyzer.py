import asyncio
import os
import random
import re
import tempfile
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from playwright.async_api import async_playwright

# File types that, when downloaded from a random site, deserve suspicion.
SUSPICIOUS_EXTENSIONS = (
    ".exe", ".bat", ".cmd", ".scr", ".js", ".jar", ".vbs", ".ps1",
    ".zip", ".rar", ".7z", ".apk", ".msi", ".iso", ".dll", ".hta",
)

# Public services that pages call to learn the visitor's IP address.
IP_TRACKING_HINTS = (
    "ip-api.com",
    "ipify.org",
    "api.ipify.org",
    "ipinfo.io",
    "geoip",
    "ip2location.com",
)

# Big, well-known ad/marketing/CDN networks. Anything else serving "ads"
# is at least worth a second look.
REPUTABLE_NETWORKS = {
    "googleads", "googlesyndication", "doubleclick", "google-analytics",
    "facebook.com", "fbcdn.net", "amazon-adsystem", "amazonaws.com",
    "cloudfront.net", "cloudflare.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "bootstrapcdn.com", "maxcdn.com", "fastly.net", "gstatic.com",
    "adnxs.com", "openx.net", "pubmatic.com", "rubiconproject.com",
    "akamai", "akamaized.net",
}

# Some sites sniff for automation and serve a totally different (or blank)
# page, so we rotate UA / timezone / locale / geolocation per scan.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
]

TIMEZONES = ["UTC", "America/New_York", "Europe/Berlin", "Asia/Singapore"]
LOCALES = ["en-US", "en-GB", "de-DE", "fr-FR"]
GEO_COORDS = [
    {"latitude": 40.7128, "longitude": -74.0060},
    {"latitude": 52.5200, "longitude": 13.4050},
    {"latitude": 1.3521, "longitude": 103.8198},
]

STEALTH_SCRIPT = """
// Blend in: kill the usual automation tells that sites check for.
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
window.chrome = { runtime: {} };
"""

FINGERPRINTING_HINTS = (
    "fingerprintjs", "CanvasRenderingContext2D", "toDataURL",
    "WebGLRenderingContext", "AudioContext", "RTCPeerConnection",
    "hardwareConcurrency",
)


def _is_reputable(domain: str) -> bool:
    lower = domain.lower()
    return any(reputable in lower for reputable in REPUTABLE_NETWORKS)


def _looks_like_ad_request(url: str, netloc: str) -> bool:
    path_lower = urlparse(url).path.lower()
    haystack = path_lower + " " + netloc.lower()
    return any(
        token in haystack
        for token in ["ad", "ads", "banner", "popup", "pop", "track", "sponsored"]
    )


async def perform_dynamic_analysis(
    url: str,
    timeout_seconds: int = 40,
    *,
    user_agent: Optional[str] = None,
    timezone_id: Optional[str] = None,
    locale: Optional[str] = None,
    geolocation: Optional[Dict[str, float]] = None,
    screenshots_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Load the URL in a sandboxed, instrumented Chromium and collect
    everything that a normal visitor would not notice: redirects, downloads,
    popups, cross-domain requests, console errors, and a screenshot."""
    result: Dict[str, Any] = {
        "redirectChain": [],
        "finalUrl": None,
        "finalHtml": "",
        "screenshots": [],
        "downloads": [],
        "networkIndicators": {"suspicious": False, "indicators": []},
        "networkStats": {"requests": 0, "responses": 0, "bytes": 0, "failed": 0, "usedHttps": False},
        "consoleMessages": [],
        "pageErrors": [],
        "antiBot": {"blocked": False, "status": None, "reason": None},
        "fingerprinting": {"hints": []},
        "popups": {"dialogs": [], "modals": [], "sources": []},
        "thirdParty": {"domains": {}, "unknownAdDomains": [], "suspiciousPosts": []},
        "credentialExfil": {"crossOriginPasswordForms": []},
        "loadMetrics": None,
        "error": None,
    }

    indicators: List[str] = []
    ua = user_agent or random.choice(USER_AGENTS)
    tz = timezone_id or random.choice(TIMEZONES)
    loc = locale or random.choice(LOCALES)
    geo = geolocation or random.choice(GEO_COORDS)

    with tempfile.TemporaryDirectory(prefix="dl_") as download_dir:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
            )
            context = await browser.new_context(
                accept_downloads=True,
                user_agent=ua,
                timezone_id=tz,
                locale=loc,
                geolocation=geo,
                permissions=["geolocation"],
            )

            downloaded_items: List[Dict[str, Any]] = []

            async def on_download(download):
                suggested = download.suggested_filename
                try:
                    save_path = os.path.join(download_dir, suggested)
                    await download.save_as(save_path)
                    downloaded_items.append({"filename": suggested, "path": save_path})
                except Exception:
                    downloaded_items.append({"filename": suggested, "path": ""})

            context.on("download", on_download)

            page = await context.new_page()
            await page.add_init_script(STEALTH_SCRIPT)

            redirect_chain: List[str] = []
            first_status: Optional[int] = None
            base_host: Optional[str] = None
            third_party_counts: Dict[str, int] = {}
            unknown_ad_domains: set[str] = set()
            suspicious_posts: List[Dict[str, Any]] = []
            popup_sources: List[Dict[str, Any]] = []
            console_messages: List[Dict[str, str]] = []
            page_errors: List[str] = []
            stats = {"requests": 0, "responses": 0, "bytes": 0, "failed": 0, "https": False}

            async def on_dialog(dialog):
                try:
                    msg = dialog.message
                except Exception:
                    msg = "(unknown)"
                result["popups"]["dialogs"].append(str(msg)[:500])
                try:
                    frame = await dialog.frame()
                    frame_url = frame.url if frame else None
                    popup_sources.append({"type": "js_dialog", "message": str(msg)[:200], "source": frame_url})
                except Exception:
                    pass
                try:
                    await dialog.dismiss()
                except Exception:
                    pass

            async def on_request(request):
                nonlocal base_host
                if base_host is None:
                    try:
                        base_host = urlparse(page.url).netloc or None
                    except Exception:
                        base_host = None
                req_url = request.url
                stats["requests"] += 1
                if req_url.lower().startswith("https"):
                    stats["https"] = True
                if request.method == "POST":
                    body = request.post_data or ""
                    if body:
                        if len(body) > 128 and re.search(r"[A-Za-z0-9+/=]{64,}", body):
                            suspicious_posts.append({
                                "url": req_url, "length": len(body), "reason": "high_entropy_body",
                            })
                        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", body):
                            suspicious_posts.append({
                                "url": req_url, "length": len(body), "reason": "contains_ip",
                            })
                try:
                    netloc = urlparse(req_url).netloc
                    if base_host and netloc and netloc != base_host:
                        third_party_counts[netloc] = third_party_counts.get(netloc, 0) + 1
                        if not _is_reputable(netloc) and _looks_like_ad_request(req_url, netloc):
                            unknown_ad_domains.add(netloc)
                except Exception:
                    pass
                if any(h in req_url.lower() for h in IP_TRACKING_HINTS):
                    indicators.append("ip-tracking-request")

            async def on_response(response):
                nonlocal first_status
                try:
                    if first_status is None:
                        first_status = response.status
                    stats["responses"] += 1
                    headers = response.headers
                    try:
                        body = await response.body()
                        stats["bytes"] += len(body)
                    except Exception:
                        pass
                    disp = headers.get("content-disposition", "").lower()
                    if "attachment" in disp:
                        indicators.append("content-disposition-attachment")
                    if any(response.url.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                        indicators.append("suspicious-extension")
                except Exception:
                    pass

            async def on_request_failed(request):
                stats["failed"] += 1

            async def on_console(msg):
                if msg.type in ("error", "warning") and len(console_messages) < 40:
                    console_messages.append({"type": msg.type, "text": (msg.text or "")[:300]})

            async def on_pageerror(err):
                if len(page_errors) < 20:
                    page_errors.append(str(err)[:300])

            page.on("dialog", on_dialog)
            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", on_request_failed)
            page.on("console", on_console)
            page.on("pageerror", on_pageerror)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                redirect_chain.append(page.url)
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(6000, timeout_seconds * 1000))
                except Exception:
                    pass
                for _ in range(3):
                    prev = page.url
                    await asyncio.sleep(1)
                    if page.url != prev:
                        redirect_chain.append(page.url)

                html = await page.content()
                lower = html.lower()
                result["fingerprinting"]["hints"] = [h for h in FINGERPRINTING_HINTS if h.lower() in lower]

                # Modals / overlays
                modals: List[Dict[str, Any]] = []
                try:
                    for loc in await page.locator('[role="dialog"]').all():
                        try:
                            txt = await loc.inner_text()
                            if txt and len(txt.strip()) > 10:
                                z_idx = await loc.evaluate("el => window.getComputedStyle(el).zIndex")
                                frame = await loc.frame()
                                frame_url = frame.url if frame else None
                                modals.append({"text": txt.strip()[:500], "zIndex": z_idx, "source": frame_url})
                                popup_sources.append({"type": "html_modal", "text": txt.strip()[:200], "source": frame_url})
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    high_z = await page.evaluate("""
                        () => {
                            const els = Array.from(document.querySelectorAll('div, section, aside'));
                            return els.filter(el => {
                                const style = window.getComputedStyle(el);
                                const z = parseInt(style.zIndex) || 0;
                                return z > 999 && (el.offsetWidth > 200 || el.offsetHeight > 200);
                            }).map(el => ({
                                text: el.innerText.trim().substring(0, 500),
                                zIndex: parseInt(window.getComputedStyle(el).zIndex) || 0,
                                visible: el.offsetParent !== null
                            }));
                        }
                    """)
                    for item in high_z[:10]:
                        if item.get("text") and item.get("visible"):
                            modals.append(item)
                            popup_sources.append({"type": "high_z_overlay", "text": item.get("text", "")[:200], "source": None})
                except Exception:
                    pass

                # Cross-origin password forms = classic credential harvesting.
                try:
                    cross_origin_forms = await page.evaluate("""
                        () => {
                            const target = location.origin;
                            const hits = [];
                            for (const f of document.querySelectorAll('form')) {
                                if (!f.querySelector('input[type=password]')) continue;
                                const action = (f.action || '').trim();
                                if (!action) continue;
                                let dest;
                                try { dest = new URL(action, location.href); }
                                catch (e) { continue; }
                                if (dest.origin !== target) hits.push(dest.href);
                            }
                            return hits.slice(0, 20);
                        }
                    """)
                    result["credentialExfil"]["crossOriginPasswordForms"] = cross_origin_forms or []
                    if cross_origin_forms:
                        indicators.append("cross-origin-password-form")
                except Exception:
                    pass

                # Performance numbers (nice for the trace display).
                try:
                    result["loadMetrics"] = await page.evaluate("""
                        () => {
                            const nav = performance.getEntriesByType('navigation')[0];
                            if (!nav) return null;
                            return {
                                domContentLoaded: Math.round(nav.domContentLoadedEventEnd - nav.fetchStart),
                                load: Math.round(nav.loadEventEnd - nav.fetchStart),
                                transferredBytes: nav.transferSize
                            };
                        }
                    """)
                except Exception:
                    result["loadMetrics"] = None

                # Screenshot for the human reading the report.
                if screenshots_dir:
                    try:
                        os.makedirs(screenshots_dir, exist_ok=True)
                        shot_name = f"{uuid.uuid4().hex}.png"
                        await page.screenshot(
                            path=os.path.join(screenshots_dir, shot_name),
                            full_page=True,
                            type="png",
                        )
                        result["screenshots"].append(f"/static/screenshots/{shot_name}")
                    except Exception:
                        pass

                result["finalHtml"] = html
                result["finalUrl"] = page.url
                result["redirectChain"] = redirect_chain
                result["consoleMessages"] = console_messages
                result["pageErrors"] = page_errors
                result["popups"]["modals"] = modals
                result["popups"]["sources"] = popup_sources

                if first_status in (403, 429):
                    result["antiBot"] = {"blocked": True, "status": first_status, "reason": "http_status"}
                elif re.search(r"captcha|are you human|access denied|blocked by", lower):
                    result["antiBot"] = {"blocked": True, "status": first_status, "reason": "captcha_or_bot_text"}

            except Exception as e:
                result["error"] = str(e)
            finally:
                result["downloads"] = downloaded_items
                result["thirdParty"] = {
                    "domains": dict(sorted(third_party_counts.items(), key=lambda kv: kv[1], reverse=True)[:50]),
                    "unknownAdDomains": sorted(list(unknown_ad_domains))[:50],
                    "suspiciousPosts": suspicious_posts[:50],
                }
                await context.close()
                await browser.close()

    if len(result.get("redirectChain", [])) > 3:
        indicators.append("multi-stage-redirects")

    result["networkIndicators"] = {
        "suspicious": len(set(indicators)) > 0,
        "indicators": sorted(list(set(indicators))),
        "fingerprint": {"ua": ua, "tz": tz, "locale": loc},
    }
    result["networkStats"] = {
        "requests": stats["requests"],
        "responses": stats["responses"],
        "bytes": stats["bytes"],
        "failed": stats["failed"],
        "usedHttps": stats["https"],
    }
    return result
