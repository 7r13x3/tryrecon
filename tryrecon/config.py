"""
TryRecon — Config loader
"""
import sys
from dataclasses import dataclass, field
from typing import Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class ScanCfg:
    timeout: int = 5
    concurrency: int = 100
    user_agent: str = "TryRecon/1.0"


@dataclass
class SubdomainsCfg:
    use_crtsh: bool = True
    use_hackertarget: bool = True
    use_cyberatlas: bool = True
    use_bruteforce: bool = True
    wordlist: str = "wordlists/subdomains.txt"


@dataclass
class PortsCfg:
    top_ports: int = 1000
    use_internetdb: bool = True
    banner_timeout: int = 3


@dataclass
class TechCfg:
    follow_redirects: bool = True
    max_redirects: int = 5


@dataclass
class FaviconCfg:
    enabled: bool = True
    censys_key: str = ""
    fofa_key: str = ""


@dataclass
class EmailsCfg:
    scrape_site: bool = True
    tomba_key: str = ""
    verify_smtp: bool = True
    pattern_infer: bool = True


@dataclass
class BreachCfg:
    use_xposedornot: bool = True
    use_leaklookup: bool = False


@dataclass
class PhoneCfg:
    use_libphonenumber: bool = True
    default_region: str = "US"
    numverify_key: str = ""
    veriphone_key: str = ""


@dataclass
class Config:
    scan: ScanCfg = field(default_factory=ScanCfg)
    subdomains: SubdomainsCfg = field(default_factory=SubdomainsCfg)
    ports: PortsCfg = field(default_factory=PortsCfg)
    tech: TechCfg = field(default_factory=TechCfg)
    favicon: FaviconCfg = field(default_factory=FaviconCfg)
    emails: EmailsCfg = field(default_factory=EmailsCfg)
    breach: BreachCfg = field(default_factory=BreachCfg)
    phone: PhoneCfg = field(default_factory=PhoneCfg)


def load(path: str) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    def _get(section, key, default):
        return data.get(section, {}).get(key, default)

    cfg = Config(
        scan=ScanCfg(
            timeout=int(_get("scan", "timeout", 5)),
            concurrency=int(_get("scan", "concurrency", 100)),
            user_agent=_get("scan", "user_agent", "TryRecon/1.0"),
        ),
        subdomains=SubdomainsCfg(
            use_crtsh=bool(_get("subdomains", "use_crtsh", True)),
            use_hackertarget=bool(_get("subdomains", "use_hackertarget", True)),
            use_cyberatlas=bool(_get("subdomains", "use_cyberatlas", True)),
            use_bruteforce=bool(_get("subdomains", "use_bruteforce", True)),
            wordlist=_get("subdomains", "wordlist",
                          "wordlists/subdomains.txt"),
        ),
        ports=PortsCfg(
            top_ports=int(_get("ports", "top_ports", 1000)),
            use_internetdb=bool(_get("ports", "use_internetdb", True)),
            banner_timeout=int(_get("ports", "banner_timeout", 3)),
        ),
        tech=TechCfg(
            follow_redirects=bool(_get("tech", "follow_redirects", True)),
            max_redirects=int(_get("tech", "max_redirects", 5)),
        ),
        favicon=FaviconCfg(
            enabled=bool(_get("favicon", "enabled", True)),
            censys_key=_get("favicon", "censys_key", ""),
            fofa_key=_get("favicon", "fofa_key", ""),
        ),
        emails=EmailsCfg(
            scrape_site=bool(_get("emails", "scrape_site", True)),
            tomba_key=_get("emails", "tomba_key", ""),
            verify_smtp=bool(_get("emails", "verify_smtp", True)),
            pattern_infer=bool(_get("emails", "pattern_infer", True)),
        ),
        breach=BreachCfg(
            use_xposedornot=bool(_get("breach", "use_xposedornot", True)),
            use_leaklookup=bool(_get("breach", "use_leaklookup", False)),
        ),
        phone=PhoneCfg(
            use_libphonenumber=bool(_get("phone", "use_libphonenumber", True)),
            default_region=_get("phone", "default_region", "US"),
            numverify_key=_get("phone", "numverify_key", ""),
            veriphone_key=_get("phone", "veriphone_key", ""),
        ),
    )
    return cfg
