"""
TryRecon — SQLite storage layer
Every module writes its findings here.
"""
import sqlite3
from typing import List, Dict, Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT UNIQUE NOT NULL,
    first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subdomains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER,
    name        TEXT,
    ip          TEXT,
    source      TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT,
    port        INTEGER,
    service     TEXT,
    banner      TEXT
);

CREATE TABLE IF NOT EXISTS technologies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host        TEXT,
    name        TEXT,
    version     TEXT,
    category    TEXT
);

CREATE TABLE IF NOT EXISTS emails (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT,
    email       TEXT,
    source      TEXT,
    breaches    TEXT
);

CREATE TABLE IF NOT EXISTS phones (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    number      TEXT,
    country     TEXT,
    region      TEXT,
    carrier     TEXT,
    line_type   TEXT,
    timezone    TEXT
);

CREATE TABLE IF NOT EXISTS whois_data (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT,
    registrar   TEXT,
    created     TEXT,
    expires     TEXT,
    nameservers TEXT
);
"""


class DB:
    def __init__(self, path: str = "recon.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ─── targets ───
    def add_target(self, domain: str) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO targets (domain) VALUES (?)", (domain,)
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM targets WHERE domain = ?", (domain,)
        ).fetchone()
        return row["id"]

    # ─── subdomains ───
    def add_subdomain(self, target_id: int, name: str,
                      ip: str = "", source: str = ""):
        self.conn.execute(
            "INSERT INTO subdomains (target_id, name, ip, source) "
            "VALUES (?, ?, ?, ?)",
            (target_id, name, ip, source),
        )
        self.conn.commit()

    # ─── ports ───
    def add_port(self, host: str, port: int,
                 service: str = "", banner: str = ""):
        self.conn.execute(
            "INSERT INTO ports (host, port, service, banner) "
            "VALUES (?, ?, ?, ?)",
            (host, port, service, banner),
        )
        self.conn.commit()

    # ─── technologies ───
    def add_tech(self, host: str, name: str,
                 version: str = "", category: str = ""):
        self.conn.execute(
            "INSERT INTO technologies (host, name, version, category) "
            "VALUES (?, ?, ?, ?)",
            (host, name, version, category),
        )
        self.conn.commit()

    # ─── emails ───
    def add_email(self, domain: str, email: str,
                  source: str = "", breaches: str = ""):
        self.conn.execute(
            "INSERT INTO emails (domain, email, source, breaches) "
            "VALUES (?, ?, ?, ?)",
            (domain, email, source, breaches),
        )
        self.conn.commit()

    # ─── phones ───
    def add_phone(self, number: str, country: str = "", region: str = "",
                  carrier: str = "", line_type: str = "", timezone: str = ""):
        self.conn.execute(
            "INSERT INTO phones (number, country, region, carrier, "
            "line_type, timezone) VALUES (?, ?, ?, ?, ?, ?)",
            (number, country, region, carrier, line_type, timezone),
        )
        self.conn.commit()

    # ─── whois ───
    def add_whois(self, domain: str, registrar: str, created: str,
                  expires: str, nameservers: str):
        self.conn.execute(
            "INSERT INTO whois_data (domain, registrar, created, "
            "expires, nameservers) VALUES (?, ?, ?, ?, ?)",
            (domain, registrar, created, expires, nameservers),
        )
        self.conn.commit()

    # ─── queries ───
    def get_subdomains(self, target_id: int) -> List[Dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_ports(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM ports").fetchall()
        return [dict(r) for r in rows]

    def get_emails(self) -> List[Dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM emails").fetchall()
        return [dict(r) for r in rows]

    def counts(self) -> Dict[str, int]:
        return {
            "Subdomains":   self.conn.execute(
                "SELECT COUNT(*) FROM subdomains").fetchone()[0],
            "Open ports":   self.conn.execute(
                "SELECT COUNT(*) FROM ports").fetchone()[0],
            "Technologies": self.conn.execute(
                "SELECT COUNT(*) FROM technologies").fetchone()[0],
            "Emails":       self.conn.execute(
                "SELECT COUNT(*) FROM emails").fetchone()[0],
            "Phones":       self.conn.execute(
                "SELECT COUNT(*) FROM phones").fetchone()[0],
        }

    def close(self):
        self.conn.close()
