"""
TryRecon — Utilities
"""
import re
import socket


DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def ensure_scheme(url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return f"https://{url}"


def truncate(text: str, n: int = 80) -> str:
    if not text:
        return ""
    return text if len(text) <= n else text[: n - 3] + "..."


def uniq(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
