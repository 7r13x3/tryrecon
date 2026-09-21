"""
TryRecon — CLI entry point
"""
import argparse
import asyncio
import sys

from .config import load
from .db import DB
from . import logger
from . import __version__

from .modules import (
    subdomains, portscan, tech, favicon, emails, phone,
    breach, whois_lookup, asn, buckets, takeover, wayback,
)
from .report import html as report_html


# ─────────────────────────────────────────────────────────────
#  Commands
# ─────────────────────────────────────────────────────────────

async def _run_scan(args):
    cfg = load(args.config)

    if not args.subdomains and not args.ports and not args.full:
        # default: full scan
        args.full = True

    db = DB("recon.db")
    target_id = db.add_target(args.domain)

    subs = []
    hosts = [args.domain]

    # ── Phase 1: Subdomains ──
    if args.full or args.subdomains:
        subs = await subdomains.enumerate(args.domain, cfg, db, target_id)
        hosts = [args.domain] + [s["name"] for s in subs]

    # ── Phase 2: Ports ──
    if args.full or args.ports:
        ports = await portscan.scan(hosts, cfg, db)
    else:
        ports = []

    # ── Phase 4: Tech detection ──
    if args.full:
        await tech.scan(hosts, cfg, db)

    # ── Phase 5: Favicon ──
    if args.full:
        await favicon.scan(hosts, cfg, db)

    # ── Phase 6: Emails ──
    if args.full:
        email_list = await emails.scan(args.domain, cfg, db)
    else:
        email_list = []

    # ── Phase 7: Breaches ──
    if args.full and email_list:
        await breach.enrich_emails(email_list, cfg, db)

    # ── Phase 8: WHOIS ──
    if args.full:
        whois_lookup.scan(args.domain, db)

    # ── Phase 9: ASN expansion ──
    if args.full:
        await asn.expand(args.domain)

    # ── Phase 10: Buckets ──
    if args.full:
        await buckets.scan(args.domain, cfg)

    # ── Phase 11: Takeover ──
    if args.full and subs:
        await takeover.scan(subs, cfg)

    # ── Phase 12: Wayback ──
    if args.full:
        await wayback.scan(args.domain, cfg)

    # ── Summary + report ──
    logger.summary(db.counts())

    if args.report:
        report_html.generate(db, args.domain, args.report)

    db.close()


def cmd_scan(args):
    logger.banner()
    asyncio.run(_run_scan(args))


def cmd_check(args):
    try:
        cfg = load(args.config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        sys.exit(1)

    logger.success("Config OK")
    logger.info(f"Timeout:      {cfg.scan.timeout}s")
    logger.info(f"Concurrency:  {cfg.scan.concurrency}")
    logger.info(f"Subdomains:   crt.sh={cfg.subdomains.use_crtsh} "
                f"brute={cfg.subdomains.use_bruteforce}")
    logger.info(f"Port scan:    top {cfg.ports.top_ports}")
    logger.info(f"Breach:       xposedornot={cfg.breach.use_xposedornot}")
    logger.info(f"Phone region: {cfg.phone.default_region}")


def cmd_phone(args):
    cfg = load(args.config)
    logger.banner()

    if args.file:
        try:
            with open(args.file) as f:
                numbers = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Cannot read file: {e}")
            sys.exit(1)
        phone.cli_batch(numbers, cfg)
    elif args.number:
        phone.cli_analyze(args.number, cfg)
    else:
        logger.error("Provide a number or --file")
        sys.exit(1)


def cmd_report(args):
    db = DB(args.db)
    report_html.generate(db, args.domain, args.out)
    db.close()


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="tryrecon",
        description="TryRecon — OSINT reconnaissance framework",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # ── scan ──
    p_scan = sub.add_parser("scan", help="Run reconnaissance")
    p_scan.add_argument("domain", help="Target domain (must be authorized)")
    p_scan.add_argument("--config", "-c",
                        default="configs/example.toml")
    p_scan.add_argument("--full", action="store_true",
                        help="Run every module")
    p_scan.add_argument("--subdomains", action="store_true",
                        help="Only subdomain enumeration")
    p_scan.add_argument("--ports", action="store_true",
                        help="Only port scanning")
    p_scan.add_argument("--report", default="report.html",
                        help="Output HTML report path")
    p_scan.set_defaults(func=cmd_scan)

    # ── check ──
    p_check = sub.add_parser("check", help="Validate config")
    p_check.add_argument("--config", "-c",
                         default="configs/example.toml")
    p_check.set_defaults(func=cmd_check)

    # ── phone ──
    p_phone = sub.add_parser("phone", help="Phone number OSINT")
    p_phone.add_argument("number", nargs="?", help="Phone number")
    p_phone.add_argument("--file", help="File with one number per line")
    p_phone.add_argument("--config", "-c",
                         default="configs/example.toml")
    p_phone.set_defaults(func=cmd_phone)

    # ── report ──
    p_report = sub.add_parser("report", help="Regenerate HTML from DB")
    p_report.add_argument("--db", default="recon.db")
    p_report.add_argument("--domain", required=True)
    p_report.add_argument("--out", default="report.html")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
