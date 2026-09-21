"""
TryRecon — ASN / BGP Expansion
Finds the ASN that owns an IP, then lists every CIDR range
that ASN owns. Uses BGPView (free, no key).

Example:
    IPv4 8.8.8.8 → AS15169 (Google LLC) → 200+ CIDR ranges
"""
import socket
from typing import Dict, List

import httpx

from .. import logger


async def ip_to_asn(ip: str) -> Dict:
    url = f"https://api.bgpview.io/ip/{ip}"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url)
            if r.status_code == 200:
                data = r.json().get("data", {})
                prefixes = data.get("prefixes", [])
                if prefixes:
                    return {
                        "ip": ip,
                        "asn": prefixes[0].get("asn", {}).get("asn"),
                        "name": prefixes[0].get("asn", {}).get("name"),
                        "description": prefixes[0].get("asn", {}).get("description"),
                        "country": prefixes[0].get("asn", {}).get("country_code"),
                    }
    except Exception as e:
        logger.warn(f"BGPView IP lookup failed: {e}")
    return {}


async def asn_to_prefixes(asn: int) -> List[str]:
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url)
            if r.status_code == 200:
                data = r.json().get("data", {})
                ipv4 = [p.get("prefix") for p in data.get("ipv4_prefixes", [])]
                return ipv4
    except Exception as e:
        logger.warn(f"BGPView ASN lookup failed: {e}")
    return []


async def expand(domain: str) -> Dict:
    """Resolve domain → IP → ASN → all CIDRs owned by that ASN."""
    logger.phase(9, "ASN / BGP Expansion")

    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        logger.sub(f"DNS resolution failed: {e}")
        return {}

    logger.sub(f"Resolved {domain} → {ip}")

    info = await ip_to_asn(ip)
    if not info:
        logger.sub("Could not determine ASN")
        return {}

    asn = info["asn"]
    logger.sub(f"ASN: {asn} — {info.get('name')} ({info.get('country')})")

    prefixes = await asn_to_prefixes(asn)
    logger.sub(f"Total CIDR ranges: {len(prefixes)}")
    for p in prefixes[:10]:
        logger.sub(f"  {p}")
    if len(prefixes) > 10:
        logger.sub(f"  ... and {len(prefixes) - 10} more")

    return {
        "ip": ip,
        "asn": asn,
        "name": info.get("name", ""),
        "country": info.get("country", ""),
        "prefixes": prefixes,
    }
