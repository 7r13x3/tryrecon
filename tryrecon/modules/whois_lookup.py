"""
TryRecon — WHOIS Lookup
Uses python-whois library (free, no key).
"""
from typing import Dict

import whois as pywhois

from .. import logger


def _clean(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:5])
    return str(value)


def lookup(domain: str) -> Dict[str, str]:
    """Perform WHOIS lookup and return structured data."""
    try:
        w = pywhois.whois(domain)
        data = {
            "domain":       domain,
            "registrar":    _clean(w.registrar),
            "created":      _clean(w.creation_date),
            "expires":      _clean(w.expiration_date),
            "updated":      _clean(w.updated_date),
            "nameservers":  _clean(w.name_servers),
            "status":       _clean(w.status),
            "emails":       _clean(w.emails),
            "country":      _clean(w.country),
            "org":          _clean(w.org),
        }
        return data
    except Exception as e:
        logger.warn(f"WHOIS failed for {domain}: {e}")
        return {"domain": domain, "error": str(e)}


def scan(domain: str, db) -> Dict[str, str]:
    logger.phase(8, "WHOIS Lookup")

    data = lookup(domain)
    if "error" in data:
        logger.sub(f"Failed: {data['error']}")
        return data

    logger.sub(f"Registrar:   {data['registrar']}")
    logger.sub(f"Created:     {data['created']}")
    logger.sub(f"Expires:     {data['expires']}")
    logger.sub(f"Nameservers: {data['nameservers']}")
    logger.sub(f"Country:     {data['country']}")
    logger.sub(f"Org:         {data['org']}")

    db.add_whois(
        domain,
        data.get("registrar", ""),
        data.get("created", ""),
        data.get("expires", ""),
        data.get("nameservers", ""),
    )
    return data
