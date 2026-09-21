"""
TryRecon — Email Harvesting
Sources:
  - Site scraping (mailto: links, contact pages)
  - Optional Tomba.io free tier
  - Pattern inference from found emails
"""
import re
from typing import List, Set

import httpx
from bs4 import BeautifulSoup

from .. import logger


EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

COMMON_PAGES = [
    "", "/contact", "/about", "/team", "/careers",
    "/support", "/privacy", "/terms", "/impressum",
]


async def scrape_site(domain: str, cfg) -> Set[str]:
    """Crawl a few common pages of the target and extract emails."""
    found: Set[str] = set()
    base_urls = [f"https://{domain}", f"http://{domain}"]

    for base in base_urls:
        try:
            async with httpx.AsyncClient(
                timeout=cfg.scan.timeout,
                follow_redirects=True,
                headers={"User-Agent": cfg.scan.user_agent},
            ) as c:
                for page in COMMON_PAGES:
                    try:
                        r = await c.get(base + page)
                        if r.status_code != 200:
                            continue
                        soup = BeautifulSoup(r.text, "html.parser")

                        # mailto: links
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            if href.startswith("mailto:"):
                                email = href[7:].split("?")[0]
                                if domain in email:
                                    found.add(email.lower())

                        # raw text
                        for m in EMAIL_RE.finditer(r.text):
                            email = m.group(0).lower()
                            if email.endswith(domain):
                                found.add(email)
                    except Exception:
                        continue
        except Exception:
            pass

    return found


async def from_tomba(domain: str, api_key: str) -> Set[str]:
    """Optional: Tomba.io free tier (25/month)."""
    if not api_key:
        return set()

    url = f"https://api.tomba.io/v1/domain-search?domain={domain}"
    headers = {"X-Tomba-Key": api_key, "X-Tomba-Secret": ""}
    found = set()
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, headers=headers)
            if r.status_code == 200:
                for entry in r.json().get("data", {}).get("emails", []):
                    email = entry.get("email", "").lower()
                    if email:
                        found.add(email)
    except Exception as e:
        logger.warn(f"Tomba failed: {e}")
    return found


def infer_patterns(found_emails: Set[str], domain: str) -> Set[str]:
    """Guess common patterns from found emails."""
    guesses: Set[str] = set()
    if not found_emails:
        return guesses

    # extract first/last names from found emails
    names = set()
    for email in found_emails:
        local = email.split("@")[0]
        parts = re.split(r"[._\-]", local)
        if len(parts) >= 2 and parts[0].isalpha() and parts[-1].isalpha():
            names.add((parts[0], parts[-1]))

    # common patterns
    for first, last in names:
        guesses.add(f"{first}.{last}@{domain}")
        guesses.add(f"{first}{last}@{domain}")
        guesses.add(f"{first[0]}{last}@{domain}")
        guesses.add(f"{first}@{domain}")

    return guesses - found_emails


async def scan(domain: str, cfg, db) -> List[dict]:
    logger.phase(6, "Email Harvesting")

    results: dict[str, str] = {}

    if cfg.emails.scrape_site:
        scraped = await scrape_site(domain, cfg)
        logger.sub(f"Site scraping: {len(scraped)} emails")
        for e in scraped:
            results.setdefault(e, "scrape")

    if cfg.emails.tomba_key:
        tomba = await from_tomba(domain, cfg.emails.tomba_key)
        logger.sub(f"Tomba.io:      {len(tomba)} emails")
        for e in tomba:
            results.setdefault(e, "tomba")

    # pattern inference (informational only — no verification by default)
    if cfg.emails.pattern_infer and results:
        guesses = infer_patterns(set(results.keys()), domain)
        logger.sub(f"Pattern guesses: {len(guesses)} (unverified)")

    # store in DB
    output = []
    for email, source in sorted(results.items()):
        db.add_email(domain, email, source, "")
        output.append({"email": email, "source": source, "breaches": []})

    logger.sub(f"Total unique:  {len(output)} emails")
    return output
