"""
TryRecon — Technology Fingerprinting
Detects web technologies from HTTP headers + HTML body.
Wappalyzer-style, no API needed.
"""
import re
from typing import Dict, List

import httpx

from .. import logger


# ─────────────────────────────────────────────────────────────
#  Fingerprint database
#  (name, category, source, pattern)
#  source: "header" | "html" | "cookie"
# ─────────────────────────────────────────────────────────────

FINGERPRINTS = [
    # ─── Web servers ───
    ("nginx",         "Web Server",  "header", r"nginx(?:/([\d.]+))?"),
    ("Apache",        "Web Server",  "header", r"Apache(?:/([\d.]+))?"),
    ("IIS",           "Web Server",  "header", r"Microsoft-IIS/([\d.]+)"),
    ("LiteSpeed",     "Web Server",  "header", r"LiteSpeed"),
    ("Caddy",         "Web Server",  "header", r"Caddy"),
    ("Cloudflare",    "CDN",         "header", r"cloudflare"),
    ("Akamai",        "CDN",         "header", r"akamai"),
    ("Fastly",        "CDN",         "header", r"fastly"),

    # ─── Languages / Frameworks (headers) ───
    ("PHP",           "Language",    "header", r"PHP/([\d.]+)"),
    ("ASP.NET",       "Framework",   "header", r"ASP\.NET"),
    ("Express",       "Framework",   "header", r"Express"),
    ("Next.js",       "Framework",   "header", r"Next\.js"),
    ("Nuxt",          "Framework",   "header", r"Nuxt"),
    ("Laravel",       "Framework",   "cookie", r"laravel_session"),
    ("Django",        "Framework",   "cookie", r"csrftoken"),
    ("Rails",         "Framework",   "cookie", r"_rails"),

    # ─── CMS ───
    ("WordPress",     "CMS",         "html",   r"/wp-content/"),
    ("WordPress",     "CMS",         "html",   r"/wp-includes/"),
    ("Drupal",        "CMS",         "header", r"Drupal"),
    ("Drupal",        "CMS",         "html",   r"Drupal\.settings"),
    ("Joomla",        "CMS",         "html",   r"/components/com_"),
    ("Magento",       "CMS",         "html",   r"Magento"),
    ("Shopify",       "CMS",         "header", r"shopify"),
    ("Ghost",         "CMS",         "html",   r"ghost-url"),

    # ─── JS Frameworks ───
    ("React",         "JS Framework", "html",  r"react(?:\.production\.min)?\.js"),
    ("React",         "JS Framework", "html",  r"__REACT_DEVTOOLS"),
    ("Vue.js",        "JS Framework", "html",  r"vue(?:\.min)?\.js"),
    ("Angular",       "JS Framework", "html",  r"angular(?:\.min)?\.js"),
    ("jQuery",        "JS Library",   "html",  r"jquery[.-]?([\d.]+)?"),
    ("Bootstrap",     "CSS Framework","html",  r"bootstrap[.-]?([\d.]+)?"),
    ("TailwindCSS",   "CSS Framework","html",  r"tailwind"),
    ("Svelte",        "JS Framework", "html",  r"svelte"),

    # ─── Analytics ───
    ("Google Analytics","Analytics",  "html",  r"google-analytics\.com"),
    ("Google Tag Manager","Analytics","html",  r"googletagmanager\.com"),
    ("Hotjar",        "Analytics",    "html",  r"hotjar"),
    ("Mixpanel",      "Analytics",    "html",  r"mixpanel"),
    ("Segment",       "Analytics",    "html",  r"segment\.(?:io|com)"),

    # ─── Misc ───
    ("Stripe",        "Payment",      "html",  r"stripe\.com"),
    ("PayPal",        "Payment",      "html",  r"paypal\.com"),
    ("Intercom",      "Chat",         "html",  r"intercom"),
    ("Zendesk",       "Chat",         "html",  r"zendesk"),
    ("reCAPTCHA",     "Security",     "html",  r"recaptcha"),
    ("hCaptcha",      "Security",     "html",  r"hcaptcha"),
]


def _match(text: str, pattern: str):
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        try:
            version = m.group(1) if m.groups() else ""
        except IndexError:
            version = ""
        return version or ""
    return None


async def fingerprint(url: str, cfg) -> List[Dict]:
    """Return list of detected technologies for a URL."""
    found: Dict[str, Dict] = {}

    try:
        async with httpx.AsyncClient(
            timeout=cfg.scan.timeout,
            follow_redirects=cfg.tech.follow_redirects,
            max_redirects=cfg.tech.max_redirects,
            headers={"User-Agent": cfg.scan.user_agent},
        ) as c:
            r = await c.get(url)
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            cookies = "\n".join(
                f"{k}={v}" for k, v in r.cookies.items()
            )
            body = r.text or ""
    except Exception as e:
        logger.warn(f"Tech fingerprint failed for {url}: {e}")
        return []

    for name, category, source, pattern in FINGERPRINTS:
        if source == "header":
            text = headers
        elif source == "cookie":
            text = cookies
        else:
            text = body

        version = _match(text, pattern)
        if version is not None:
            if name not in found:
                found[name] = {
                    "name": name,
                    "version": version,
                    "category": category,
                }

    # Detect Server header even if not in DB
    server = r.headers.get("server", "")
    if server and "nginx" not in server.lower() \
            and "apache" not in server.lower():
        found.setdefault("server-banner", {
            "name": "Server",
            "version": server,
            "category": "Web Server",
        })

    return list(found.values())


async def scan(hosts: List[str], cfg, db) -> List[Dict]:
    logger.phase(4, "Technology Detection")

    all_techs: List[Dict] = []
    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            techs = await fingerprint(url, cfg)
            if techs:
                logger.sub(f"{url}: {len(techs)} technologies")
                for t in techs:
                    db.add_tech(host, t["name"], t["version"], t["category"])
                all_techs.extend(techs)
                break

    logger.sub(f"Total: {len(all_techs)} technologies detected")
    return all_techs
