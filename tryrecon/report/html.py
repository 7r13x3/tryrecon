"""
TryRecon — HTML Report Generator
Uses Jinja2 to render a self-contained HTML report from the SQLite DB.
"""
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import logger


TEMPLATES_DIR = Path(__file__).parent / "templates"


def _env():
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def generate(db, domain: str, out_path: str = "report.html"):
    """Read everything from the DB and produce an HTML report."""
    logger.phase(99, "Generating HTML Report")

    target_row = db.conn.execute(
        "SELECT id FROM targets WHERE domain = ?", (domain,)
    ).fetchone()
    target_id = target_row["id"] if target_row else 0

    subdomains = db.conn.execute(
        "SELECT * FROM subdomains WHERE target_id = ?", (target_id,)
    ).fetchall()
    ports = db.conn.execute("SELECT * FROM ports").fetchall()
    techs = db.conn.execute("SELECT * FROM technologies").fetchall()
    emails = db.conn.execute("SELECT * FROM emails").fetchall()
    phones = db.conn.execute("SELECT * FROM phones").fetchall()
    whois_rows = db.conn.execute(
        "SELECT * FROM whois_data WHERE domain = ?", (domain,)
    ).fetchall()

    env = _env()
    template = env.get_template("report.html")

    html = template.render(
        domain=domain,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        subdomains=[dict(r) for r in subdomains],
        ports=[dict(r) for r in ports],
        techs=[dict(r) for r in techs],
        emails=[dict(r) for r in emails],
        phones=[dict(r) for r in phones],
        whois=[dict(r) for r in whois_rows],
        counts={
            "Subdomains":   len(subdomains),
            "Open ports":   len(ports),
            "Technologies": len(techs),
            "Emails":       len(emails),
            "Phones":       len(phones),
        },
    )

    Path(out_path).write_text(html, encoding="utf-8")
    logger.success(f"Report written to {out_path}")
    return out_path
