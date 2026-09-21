"""
TryRecon — Phone Number OSINT
Offline analysis using Google's libphonenumber (via `phonenumbers`).
Optional online enrichment via NumVerify / Veriphone (free tiers).
"""
from typing import List

import httpx
import phonenumbers
from phonenumbers import (
    carrier, geocoder, timezone as pn_timezone, number_type,
    PhoneNumberType,
)

from .. import logger


LINE_TYPES = {
    PhoneNumberType.MOBILE:                 "Mobile",
    PhoneNumberType.FIXED_LINE:             "Landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE:   "Fixed-line or Mobile",
    PhoneNumberType.TOLL_FREE:              "Toll-free",
    PhoneNumberType.PREMIUM_RATE:           "Premium-rate",
    PhoneNumberType.SHARED_COST:            "Shared-cost",
    PhoneNumberType.VOIP:                   "VoIP",
    PhoneNumberType.PERSONAL_NUMBER:        "Personal",
    PhoneNumberType.PAGER:                  "Pager",
    PhoneNumberType.UAN:                    "UAN",
    PhoneNumberType.VOICEMAIL:              "Voicemail",
    PhoneNumberType.UNKNOWN:                "Unknown",
}


def analyze(number: str, default_region: str = "US") -> dict:
    """Parse and analyze a phone number offline."""
    try:
        parsed = phonenumbers.parse(number, default_region)
    except phonenumbers.NumberParseException as e:
        return {"error": str(e), "number": number}

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)

    region_code = phonenumbers.region_code_for_number(parsed) or "-"
    region_name = geocoder.description_for_number(parsed, "en") or "-"
    carrier_name = carrier.name_for_number(parsed, "en") or "-"
    line_type = LINE_TYPES.get(number_type(parsed), "Unknown")
    tz = pn_timezone.time_zones_for_number(parsed) or ["-"]

    # flags
    flags = []
    if line_type == "VoIP":
        flags.append("⚠ VoIP number (often used for anonymity)")
    if line_type == "Toll-free":
        flags.append("ℹ Toll-free (business number)")
    if line_type == "Premium-rate":
        flags.append("⚠ Premium-rate (high cost per call)")
    if not valid and possible:
        flags.append("⚠ Possible but not valid")
    if not possible:
        flags.append("⚠ Not a possible number")

    return {
        "number":         number,
        "valid":          "✓ Yes" if valid else "✗ No",
        "possible":       "✓ Yes" if possible else "✗ No",
        "country_code":   parsed.country_code,
        "region_code":    region_code,
        "region_name":    region_name,
        "carrier":        carrier_name,
        "line_type":      line_type,
        "timezone":       tz,
        "e164":           phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164),
        "international":  phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national":       phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "flags":          flags,
    }


async def enrich_numverify(number: str, api_key: str) -> dict:
    """Optional: NumVerify free tier."""
    if not api_key:
        return {}
    url = f"http://apilayer.net/api/validate?access_key={api_key}&number={number}"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logger.warn(f"NumVerify failed: {e}")
    return {}


async def enrich_veriphone(number: str, api_key: str) -> dict:
    """Optional: Veriphone free tier."""
    if not api_key:
        return {}
    url = f"https://api.veriphone.io/v2/verify?phone={number}&key={api_key}"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception as e:
        logger.warn(f"Veriphone failed: {e}")
    return {}


async def analyze_number(number: str, cfg, db=None) -> dict:
    """Full analysis: offline + optional online enrichment."""
    result = analyze(number, cfg.phone.default_region)

    if "error" not in result:
        if cfg.phone.numverify_key:
            enriched = await enrich_numverify(number, cfg.phone.numverify_key)
            if enriched:
                result["numverify_carrier"] = enriched.get("carrier", "-")
                result["numverify_line_type"] = enriched.get("line_type", "-")

        if cfg.phone.veriphone_key:
            enriched = await enrich_veriphone(number, cfg.phone.veriphone_key)
            if enriched:
                result["veriphone_carrier"] = enriched.get("carrier", "-")

        if db is not None:
            db.add_phone(
                number=result.get("e164", number),
                country=result.get("region_name", ""),
                region=result.get("region_code", ""),
                carrier=result.get("carrier", ""),
                line_type=result.get("line_type", ""),
                timezone=", ".join(result.get("timezone", [])),
            )

    return result


def cli_analyze(number: str, cfg) -> dict:
    """Synchronous entry point for the CLI `phone` command."""
    result = analyze(number, cfg.phone.default_region)
    logger.phone_panel(result)
    return result


def cli_batch(numbers: List[str], cfg) -> List[dict]:
    results = []
    for n in numbers:
        logger.info(f"Analyzing {n}")
        results.append(analyze(n, cfg.phone.default_region))
        logger.phone_panel(results[-1])
    return results
