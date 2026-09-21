"""
TryRecon — Breach Lookup
Uses XposedOrNot (free, public API, no key required).
Optional: Leak-Lookup (requires key).
"""
from typing import List

import httpx

from .. import logger


async def check_xposedornot(email: str) -> List[str]:
    """Return list of breach names an email appears in (free, no key)."""
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            if r.status_code == 200:
                data = r.json()
                # XposedOrNot returns: {"breaches": [["Adobe","LinkedIn",...]]}
                breaches = data.get("breaches", [])
                if breaches and isinstance(breaches[0], list):
                    return breaches[0]
                if isinstance(breaches, list):
                    return breaches
    except Exception as e:
        logger.warn(f"XposedOrNot failed for {email}: {e}")
    return []


async def enrich_emails(emails: List[dict], cfg, db) -> List[dict]:
    """For each email, look up breaches and update the record."""
    logger.phase(7, "Breach Lookup")

    if not cfg.breach.use_xposedornot:
        logger.sub("Skipped (disabled in config)")
        return emails

    enriched = []
    for e in emails:
        email = e["email"]
        breaches = await check_xposedornot(email)
        e["breaches"] = breaches

        if breaches:
            logger.sub(
                f"[red]{email}[/red] in {len(breaches)} breaches: "
                f"{', '.join(breaches[:5])}"
                + ("..." if len(breaches) > 5 else "")
            )
        else:
            logger.sub(f"[green]{email}[/green] clean")

        # update DB (insert new row with breaches)
        db.add_email("", email, e.get("source", ""),
                     ",".join(breaches))
        enriched.append(e)

    total_breached = sum(1 for e in enriched if e.get("breaches"))
    logger.sub(f"Total breached: {total_breached}/{len(enriched)}")
    return enriched
