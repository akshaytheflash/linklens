import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.utils.entropy import shannon_entropy

OBFUSCATION_HINTS = ("eval(", "fromCharCode", "atob(", "btoa(", "unescape(", "document.write", "String.fromCharCode")


def parse_html_overview(html: str, base_url: str) -> Dict[str, Any]:
    overview: Dict[str, Any] = {
        "title": "",
        "textSnippet": "",
        "links": {"internal": [], "external": []},
        "iframes": {"count": 0, "hidden": 0},
        "crossSiteResources": {"forms": [], "scripts": [], "images": [], "styles": []},
        "interactionLocks": {"rightClickDisabled": False, "mouseOverManipulation": False},
        "metaRefresh": False,
        "externalBaseTag": False,
        "passwordForms": [],
        "suspiciousScripts": [],
        "externalScriptCount": 0,
        "wordCount": 0,
    }
    if not html:
        return overview

    soup = BeautifulSoup(html, "html.parser")
    title_tag = soup.find("title")
    overview["title"] = title_tag.get_text(strip=True) if title_tag else ""

    words = soup.get_text(separator=" ", strip=True).split()
    overview["textSnippet"] = " ".join(words[:120])
    overview["wordCount"] = len(words)

    base_netloc = urlparse(base_url).netloc

    def netloc_diff(u: str) -> bool:
        return urlparse(u).netloc != base_netloc

    internal: List[str] = []
    external: List[str] = []
    for a in soup.find_all("a", href=True):
        abs_url = urljoin(base_url, a.get("href"))
        if netloc_diff(abs_url):
            external.append(abs_url)
        else:
            internal.append(abs_url)
    overview["links"] = {"internal": internal[:200], "external": external[:200]}

    # <base> tag that points somewhere else can silently rewrite every
    # relative link on the page — a classic hijack.
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_href = urljoin(base_url, base_tag.get("href"))
        overview["externalBaseTag"] = netloc_diff(base_href)

    # Meta refresh redirects are another way links pretend to be one thing
    # and actually load another.
    for meta in soup.find_all("meta", attrs={"http-equiv": True}):
        if (meta.get("http-equiv") or "").lower() == "refresh":
            overview["metaRefresh"] = True

    iframes = soup.find_all("iframe")
    hidden = 0
    for fr in iframes:
        style = (fr.get("style") or "").lower()
        width = fr.get("width") or ""
        height = fr.get("height") or ""
        if "display:none" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
            hidden += 1
    overview["iframes"] = {"count": len(iframes), "hidden": hidden}

    forms_external: List[str] = []
    password_forms: List[str] = []
    for f in soup.find_all("form"):
        has_password = bool(f.find("input", attrs={"type": "password"}))
        action = f.get("action") or ""
        if action:
            abs_action = urljoin(base_url, action)
            if netloc_diff(abs_action):
                forms_external.append(abs_action)
                if has_password:
                    password_forms.append(abs_action)
    overview["crossSiteResources"]["forms"] = forms_external
    overview["passwordForms"] = password_forms

    scripts_external: List[str] = []
    suspicious_scripts: List[str] = []
    inline_scripts = []
    for s in soup.find_all("script"):
        if s.get("src"):
            src = urljoin(base_url, s.get("src"))
            if netloc_diff(src):
                scripts_external.append(src)
        else:
            inline_scripts.append(s.get_text() or "")
    overview["crossSiteResources"]["scripts"] = scripts_external
    overview["externalScriptCount"] = len(scripts_external)

    # Heuristic script scan: very long, high-entropy inline scripts with
    # obfuscation calls are a solid "this page is up to something" signal.
    for script in inline_scripts:
        clean = script.strip()
        if not clean:
            continue
        entropy = shannon_entropy(clean)
        hits = [hint for hint in OBFUSCATION_HINTS if hint in clean.lower()]
        if len(clean) > 200 and (entropy > 4.0 or len(hits) >= 1):
            suspicious_scripts.append({
                "length": len(clean),
                "entropy": round(entropy, 2),
                "obfuscationHints": hits,
            })
    overview["suspiciousScripts"] = suspicious_scripts[:10]

    images_external: List[str] = []
    for im in soup.find_all("img", src=True):
        src = urljoin(base_url, im.get("src"))
        if netloc_diff(src):
            images_external.append(src)
    overview["crossSiteResources"]["images"] = images_external[:100]

    styles_external: List[str] = []
    for link in soup.find_all("link", rel=True, href=True):
        rels = [r.lower() for r in link.get("rel")]
        if "stylesheet" in rels:
            href = urljoin(base_url, link.get("href"))
            if netloc_diff(href):
                styles_external.append(href)
    overview["crossSiteResources"]["styles"] = styles_external

    all_scripts_text = " ".join(script.get_text(separator=" ", strip=True) for script in soup.find_all("script")).lower()
    right_click_disabled = (
        "document.oncontextmenu" in all_scripts_text
        or "oncontextmenu=" in all_scripts_text
        or ("preventdefault()" in all_scripts_text and "contextmenu" in all_scripts_text)
    )
    mouse_over_manip = "onmouseover" in all_scripts_text and ("location" in all_scripts_text or "href" in all_scripts_text)

    overview["interactionLocks"] = {
        "rightClickDisabled": right_click_disabled,
        "mouseOverManipulation": mouse_over_manip,
    }

    return overview
