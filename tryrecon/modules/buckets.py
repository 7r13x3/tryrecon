"""
TryRecon — Cloud Bucket Enumeration
Checks for publicly listable S3 / Azure Blob / GCS buckets based on
common naming patterns. Direct HTTP — no API keys.
"""
import asyncio
from typing import List, Dict

import httpx

from .. import logger


SUFFIXES = [
    "", "-dev", "-staging", "-stage", "-prod", "-production",
    "-backup", "-backups", "-bak", "-data", "-files", "-public",
    "-private", "-static", "-assets", "-media", "-uploads",
    "-archive", "-logs", "-test", "-temp", "-old", "-internal",
]

# Providers: (name, url_template, list_marker)
PROVIDERS = [
    ("AWS S3",     "https://{bucket}.s3.amazonaws.com/?list-type=2",
     "<ListBucketResult"),
    ("Azure Blob", "https://{account}.blob.core.windows.net/?comp=list",
     "<EnumerationResults"),
    ("GCS",        "https://storage.googleapis.com/{bucket}/",
     "<ListBucketResult"),
]


async def check_url(client: httpx.AsyncClient, url: str,
                    marker: str, timeout: float) -> bool:
    try:
        r = await client.get(url, timeout=timeout)
        if r.status_code == 200 and marker in r.text:
            return True
    except Exception:
        pass
    return False


async def scan(domain: str, cfg) -> List[Dict]:
    logger.phase(10, "Cloud Bucket Enumeration")

    # base name is usually the org name without TLD
    base = domain.split(".")[0]
    candidates = [f"{base}{s}" for s in SUFFIXES]

    sem = asyncio.Semaphore(20)
    found: List[Dict] = []

    async with httpx.AsyncClient(
        timeout=cfg.scan.timeout,
        headers={"User-Agent": cfg.scan.user_agent},
    ) as client:

        async def check(candidate: str, provider: str, tmpl: str, marker: str):
            async with sem:
                url = tmpl.format(bucket=candidate, account=candidate)
                if await check_url(client, url, marker, cfg.scan.timeout):
                    logger.sub(f"[red]PUBLIC[/red] {provider}: {url}")
                    found.append({
                        "provider": provider,
                        "bucket": candidate,
                        "url": url,
                    })

        tasks = [
            check(c, provider, tmpl, marker)
            for c in candidates
            for provider, tmpl, marker in PROVIDERS
        ]
        await asyncio.gather(*tasks)

    if not found:
        logger.sub("No public buckets found")
    else:
        logger.sub(f"Total public buckets: {len(found)}")

    return found
