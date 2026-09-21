"""
TryRecon — Subdomain Takeover Detection
Checks if a CNAME points to a service whose resource no longer exists.
If yes → the subdomain can be hijacked.
"""
import asyncio
from typing import List, Dict

import dns.resolver
import httpx

from .. import logger


# Known fingerprints for vulnerable services
# (CNAME suffix, HTTP error body marker, service name)
FINGERPRINTS = [
    ("github.io",              "There isn't a GitHub Pages site here",
                                "GitHub Pages"),
    ("herokuapp.com",          "No such app",              "Heroku"),
    ("herokudns.com",          "No such app",              "Heroku"),
    ("s3.amazonaws.com",       "NoSuchBucket",             "AWS S3"),
    ("cloudfront.net",         "Bad request",              "AWS CloudFront"),
    ("azurewebsites.net",      "Error 404 - Web app not found",
                                "Azure Web Apps"),
    ("cloudapp.azure.com",     "Not Found",                "Azure CloudApp"),
    ("trafficmanager.net",     "Not Found",                "Azure TrafficManager"),
    ("fastly.net",             "Fastly error: unknown domain",
                                "Fastly"),
    ("pantheonsite.io",        "The gods are wise",        "Pantheon"),
    ("zendesk.com",            "Help Center Closed",       "Zendesk"),
    ("readme.io",              "Project doesnt exist",     "ReadMe.io"),
    ("surge.sh",               "project not found",        "Surge.sh"),
    ("bitbucket.io",           "Repository not found",     "Bitbucket"),
    ("netlify.app",            "Not Found - Request ID",   "Netlify"),
    ("netlify.com",            "Not Found - Request ID",   "Netlify"),
    ("vercel.app",             "The deployment could not be found",
                                "Vercel"),
    ("myshopify.com",          "Sorry, this shop is currently unavailable",
                                "Shopify"),
    ("wordpress.com",          "Do you want to register",  "WordPress.com"),
    ("tumblr.com",             "Whatever you were looking for doesn't",
                                "Tumblr"),
    ("statuspage.io",          "You are being redirected",  "Statuspage"),
    ("uservoice.com",          "This UserVoice subdomain is currently available",
                                "UserVoice"),
]


async def get_cname(host: str) -> str:
    try:
        answers = dns.resolver.resolve(host, "CNAME")
        return str(answers[0].target).rstrip(".")
    except Exception:
        return ""


async def check_candidate(client: httpx.AsyncClient, host: str,
                          timeout: float) -> Dict:
    cname = await get_cname(host)
    if not cname:
        return {}

    for suffix, marker, service in FINGERPRINTS:
        if cname.endswith(suffix):
            # try fetching and look for the fingerprint body
            for scheme in ("https", "http"):
                try:
                    r = await client.get(f"{scheme}://{host}",
                                         timeout=timeout)
                    if marker.lower() in r.text.lower():
                        return {
                            "subdomain": host,
                            "cname": cname,
                            "service": service,
                            "marker": marker,
                        }
                except Exception:
                    continue
    return {}


async def scan(subdomains: List[dict], cfg) -> List[Dict]:
    logger.phase(11, "Subdomain Takeover Detection")

    sem = asyncio.Semaphore(20)
    vulnerable: List[Dict] = []

    async with httpx.AsyncClient(
        timeout=cfg.scan.timeout,
        headers={"User-Agent": cfg.scan.user_agent},
        follow_redirects=True,
    ) as client:

        async def worker(sub: dict):
            async with sem:
                result = await check_candidate(
                    client, sub["name"], cfg.scan.timeout
                )
                if result:
                    logger.sub(
                        f"[red]VULNERABLE[/red] {result['subdomain']} → "
                        f"{result['service']} ({result['cname']})"
                    )
                    vulnerable.append(result)

        await asyncio.gather(*(worker(s) for s in subdomains))

    if not vulnerable:
        logger.sub("No takeover candidates found")
    else:
        logger.sub(f"Total vulnerable: {len(vulnerable)}")

    return vulnerable
