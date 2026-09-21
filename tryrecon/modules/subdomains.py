"""
TryRecon — Subdomain Enumeration
Sources:
  - crt.sh (Certificate Transparency logs, free, no key)
  - HackerTarget (free API, 100/day)
  - CyberAtlas (free, 2000/day)
  - DNS brute force (local wordlist)
"""
import asyncio
import socket
from typing import List, Set
from pathlib import Path

import httpx

from .. import logger


USER_AGENT = "TryRecon/1.0 (OSINT)"


# ─────────────────────────────────────────────────────────────
#  Source 1: crt.sh
# ─────────────────────────────────────────────────────────────

async def from_crtsh(domain: str, timeout: int = 20) -> Set[str]:
    """Query Certificate Transparency logs via crt.sh."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found = set()
    try:
        async with httpx.AsyncClient(timeout=timeout,
                                     headers={"User-Agent": USER_AGENT}) as c:
            r = await c.get(url)
            if r.status_code != 200:
                logger.warn(f"crt.sh returned {r.status_code}")
                return found
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(domain) and "@" not in name:
                        found.add(name)
    except Exception as e:
        logger.warn(f"crt.sh failed: {e}")
    return found


# ─────────────────────────────────────────────────────────────
#  Source 2: HackerTarget
# ─────────────────────────────────────────────────────────────

async def from_hackertarget(domain: str, timeout: int = 15) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    found = set()
    try:
        async with httpx.AsyncClient(timeout=timeout,
                                     headers={"User-Agent": USER_AGENT}) as c:
            r = await c.get(url)
            if r.status_code != 200 or "error" in r.text.lower():
                return found
            for line in r.text.splitlines():
                if "," in line:
                    name = line.split(",")[0].strip().lower()
                    if name.endswith(domain):
                        found.add(name)
    except Exception as e:
        logger.warn(f"HackerTarget failed: {e}")
    return found


# ─────────────────────────────────────────────────────────────
#  Source 3: CyberAtlas
# ─────────────────────────────────────────────────────────────

async def from_cyberatlas(domain: str, timeout: int = 15) -> Set[str]:
    url = f"https://api.cyberatlas.io/finder/?q={domain}"
    found = set()
    try:
        async with httpx.AsyncClient(timeout=timeout,
                                     headers={"User-Agent": USER_AGENT}) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return found
            data = r.json()
            for name in data.get("subdomains", []):
                name = name.strip().lower()
                if name.endswith(domain):
                    found.add(name)
    except Exception:
        pass
    return found


# ─────────────────────────────────────────────────────────────
#  Source 4: DNS brute force
# ─────────────────────────────────────────────────────────────

async def _resolve(name: str, timeout: int = 3) -> str:
    """Resolve A record, return IP or empty string."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.getaddrinfo(name, None, family=socket.AF_INET),
            timeout=timeout,
        )
        return result[0][4][0]
    except Exception:
        return ""


async def brute_force(domain: str, wordlist_path: str,
                      concurrency: int = 100) -> Set[str]:
    path = Path(wordlist_path)
    if not path.exists():
        logger.warn(f"Wordlist not found: {wordlist_path}")
        return set()

    words = [w.strip() for w in path.read_text().splitlines()
             if w.strip() and not w.startswith("#")]

    sem = asyncio.Semaphore(concurrency)
    found = set()

    async def check(word: str):
        host = f"{word}.{domain}"
        async with sem:
            ip = await _resolve(host)
            if ip:
                found.add(host)

    await asyncio.gather(*(check(w) for w in words))
    return found


# ─────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────

async def enumerate(domain: str, cfg, db, target_id: int) -> List[dict]:
    logger.phase(1, "Subdomain Enumeration")

    all_subs: dict[str, str] = {}   # name -> source

    if cfg.subdomains.use_crtsh:
        subs = await from_crtsh(domain)
        logger.sub(f"crt.sh:        {len(subs)} subdomains")
        for s in subs:
            all_subs.setdefault(s, "crt.sh")

    if cfg.subdomains.use_hackertarget:
        subs = await from_hackertarget(domain)
        logger.sub(f"HackerTarget:  {len(subs)} subdomains")
        for s in subs:
            all_subs.setdefault(s, "hackertarget")

    if cfg.subdomains.use_cyberatlas:
        subs = await from_cyberatlas(domain)
        logger.sub(f"CyberAtlas:    {len(subs)} subdomains")
        for s in subs:
            all_subs.setdefault(s, "cyberatlas")

    if cfg.subdomains.use_bruteforce:
        subs = await brute_force(
            domain, cfg.subdomains.wordlist, cfg.scan.concurrency
        )
        logger.sub(f"DNS brute:     {len(subs)} subdomains")
        for s in subs:
            all_subs.setdefault(s, "dns-brute")

    # resolve all to IPs
    results = []
    for name, source in sorted(all_subs.items()):
        ip = await _resolve(name)
        db.add_subdomain(target_id, name, ip, source)
        results.append({"name": name, "ip": ip, "source": source})

    logger.sub(f"Total unique:  {len(results)} subdomains")
    return results
