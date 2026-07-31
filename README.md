# 🔍 LinkLens

**LinkLens** is a URL safety analyzer. Paste any link and it will open the page in a
sandboxed headless Chromium, watch what the page does (redirects, downloads, popups,
network calls, console errors), scan everything with YARA malware rules, check the
domain's age and SSL cert, run the URL and page text past Gemini, and hand you back a
plain-language risk score out of 10 with a screenshot.

Built because short links and phishing pages are getting better, and "just look at the
URL" stopped being good advice.

---

## What it checks

| Check | What it looks for |
|---|---|
| **URL heuristics** | raw IPs, `@` tricks, punycode, URL shorteners, cheap TLDs, many subdomains, phishing keywords, typosquatted brand names |
| **Static preflight** | HTTP status, redirect chain, headers, missing security headers (CSP/HSTS/…) |
| **Dynamic browser** | real redirect chain, downloads, dialogs & overlays, console errors, JS exceptions, screenshots |
| **Network capture** | IP-tracking calls, cross-origin password forms, suspicious POST bodies, ad-ish third parties |
| **Page content** | hidden iframes, meta-refresh redirects, `<base>` hijacks, obfuscated inline scripts, right-click locks |
| **YARA rules** | malware, phishing, obfuscation, exploit and network-signature rules against the HTML and any downloads |
| **Domain trust** | WHOIS age + registrar, SSL validity/mismatch/expiry, resolved IPs |
| **AI (Gemini)** | reviews URL structure, page text and popup text for social-engineering patterns |

Every signal maps to a weighted category, and the UI shows a per-category score
breakdown plus a list of exactly *why* it gave the verdict.

## Verdict scale

- **MALICIOUS** (7.5+) — multiple strong indicators, e.g. credential harvesting + malware match
- **HIGH_RISK** (5.0–7.4) — several suspicious signals worth taking seriously
- **SUSPICIOUS** (3.0–4.9) — some red flags, proceed with caution
- **SAFE** (<3.0) — nothing stood out (never a guarantee!)

---

## Running locally

Requires Python 3.10+.

```bash
# 1. deps + a one-time browser download
python -m venv .venv
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # macOS/Linux
pip install -r requirements.txt
python -m playwright install chromium

# 2. optional config
copy .env.example .env            # set GEMINI_API_KEY to enable AI scoring

# 3. run
flask --app app.main run --port 8000
```

Open http://localhost:8000, paste a URL, hit Analyze.

**Running the API:** `POST /analyze` with `{"url": "https://..."}` returns the full JSON
report. `POST /scan` is the same thing but renders the HTML report instead.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## Deploying to Render

The repo ships a `Dockerfile` and a `render.yaml` blueprint.

1. Push this repo to GitHub.
2. In Render → **New → Blueprint**, point at the repo.
3. Set the `GEMINI_API_KEY` env var (optional but recommended) in the dashboard.
4. Deploy. The health check hits `/health`.

The Docker image is based on `mcr.microsoft.com/playwright/python`, so Chromium and all
its system libraries are already installed — no build step magic required. Note that
each scan launches a Chromium, so the single gunicorn worker in the `Dockerfile` is
deliberate: running more workers on Render's free tier will OOM.

> Free-tier Render instances sleep after 15 minutes of inactivity, so the first scan
> after a gap can be slow while the instance spins back up.

---

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | — | Enables AI scoring; without it the app is heuristic-only |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Model used for AI scoring |
| `ANALYSIS_TIMEOUT_SECONDS` | `40` | How long the browser gets to load the page |
| `MAX_URL_LENGTH` | `2048` | Reject URLs longer than this |
| `ALLOW_DOMAINS` / `DENY_DOMAINS` | — | Comma-separated allow/deny lists |
| `ALLOW_PRIVATE_IPS` | `false` | Allow scanning private/loopback targets (kept off to avoid SSRF-ish abuse) |
| `BLOCK_PUNYCODE` | `true` | Refuse homograph (`xn--`) domains |
| `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW_SECONDS` | `30` / `60` | Per-IP throttling |
| `LOG_SAMPLE_RATE` | `1.0` | 0–1 fraction of info/warn lines to emit |
| `SCREENSHOTS_DIR` | `app/static/screenshots` | Where captured screenshots land |

## Project layout

```
app/
  main.py                 # Flask app, routes, scoring orchestration
  config.py               # env-driven settings
  ai/gemini_client.py     # Gemini calls (structured JSON)
  analysis/               # the actual detection logic
    url_heuristics.py     # structural URL analysis + brand typosquatting
    static_fetch.py       # HEAD/GET preflight + security header check
    dynamic_analyzer.py   # headless Chromium instrumentation
    html_parse.py         # BeautifulSoup content analysis
    domain_trust.py       # WHOIS, certs, DNS
    yara_scanner.py       # per-file YARA rule loader
  scoring/verdict.py      # weighted verdict engine
  utils/                  # net, entropy, rate limiting
  templates/ static/      # UI
yararules/                # YARA rules (add your own .yar files here)
tests/                    # pytest suite
```

## Notes / limitations

- This is a *safety assist*, not a guarantee. A clean scan does **not** mean a link is
  safe — sites can behave differently for real users, and content can change.
- Some sites serve a different page to headless browsers or block them outright; the
  report will say so when it happens.
- Only scan links you are authorized to test. Scans will make real network requests to
  the target on your behalf.
- Screenshots are stored on the instance's disk and are not persistent across deploys.
