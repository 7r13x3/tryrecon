"""
TryRecon — Favicon Correlation
Compute the MMH3 hash of a favicon and (optionally) look it up in Censys.
"""
import base64
import codecs
from typing import Optional

import httpx

from .. import logger


def mmh3_hash(data: bytes) -> int:
    """Compute the Shodan-style favicon hash (base64 + mmh3)."""
    try:
        import mmh3
    except ImportError:
        # fallback: pure-python mmh3
        return _pure_mmh3(base64.encodebytes(data))
    encoded = base64.encodebytes(data)
    return mmh3.hash(encoded)


def _pure_mmh3(data: bytes) -> int:
    """Pure-python MurmurHash3 (32-bit, x86 variant)."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = 0
    roundedEnd = (length & 0xfffffffc)

    for i in range(0, roundedEnd, 4):
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) \
             | ((data[i + 2] & 0xff) << 16) \
             | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    if val in (2, 3):
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    if val in (1, 2, 3):
        k1 |= data[roundedEnd] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16

    # signed 32-bit
    if h1 >= 0x80000000:
        h1 -= 0x100000000
    return h1


async def fetch_favicon(url: str, cfg) -> Optional[bytes]:
    """Fetch /favicon.ico from a URL. Returns raw bytes or None."""
    try:
        async with httpx.AsyncClient(
            timeout=cfg.scan.timeout,
            follow_redirects=True,
            headers={"User-Agent": cfg.scan.user_agent},
        ) as c:
            r = await c.get(f"{url}/favicon.ico")
            if r.status_code == 200 and r.content:
                return r.content
    except Exception:
        pass
    return None


async def scan(hosts, cfg, db):
    logger.phase(5, "Favicon Correlation")

    if not cfg.favicon.enabled:
        logger.sub("Skipped (disabled in config)")
        return []

    results = []
    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            data = await fetch_favicon(url, cfg)
            if data:
                h = mmh3_hash(data)
                logger.sub(f"{url}/favicon.ico → mmh3:{h}")
                results.append({"host": host, "hash": h, "url": url})

                if cfg.favicon.censys_key:
                    logger.sub(
                        f"  Query Censys: "
                        f"services.http.response.favicons.md5_hash:<md5>"
                    )
                else:
                    logger.sub(
                        f"  Tip: search Shodan with: "
                        f"http.favicon.hash:{h}"
                    )
                break

    return results
