"""
TryRecon — Wayback Machine Historical URLs
Fetches every URL the Wayback Machine has ever archived for a domain.
Old URLs often expose files that were deleted but still exist on the server.
"""
from typing import List, Dict

import httpx

from .. import logger


async def fetch_urls(domain: str, timeout: int = 30) -> List[str]:
    """Fetch all archived URLs from the Wayback CDX API."""
    url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original"
        f"&collapse=urlkey&limit=5000"
    )
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.get(url)
            if r.status_code == 200:
                data = r.json()
                # first row is header ["original"]
                return [row[0] for row in data[1:] if row]
    except Exception as e:
        logger.warn(f"Wayback failed: {e}")
    return []


async def scan(domain: str, cfg) -> List[Dict]:
    logger.phase(12, "Wayback Machine Analysis")

    urls = await fetch_urls(domain, timeout=cfg.scan.timeout * 5)
    logger.sub(f"Total archived URLs: {len(urls)}")

    # interesting extensions
    interesting_ext = (
        ".env", ".git", ".bak", ".sql", ".zip", ".tar", ".gz",
        ".log", ".conf", ".config", ".xml", ".json", ".yml",
        ".yaml", ".key", ".pem", ".p12", ".db", ".sqlite",
        ".old", ".backup", ".swp", ".tmp",
    )

    interesting = [
        u for u in urls
        if any(u.lower().endswith(ext) for ext in interesting_ext)
    ]

    if interesting:
        logger.sub(f"[red]Interesting (potential leaks): {len(interesting)}[/red]")
        for u in interesting[:20]:
            logger.sub(f"  {u}")
        if len(interesting) > 20:
            logger.sub(f"  ... and {len(interesting) - 20} more")

    return [{"url": u} for u in interesting]
