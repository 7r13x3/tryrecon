"""
TryRecon — Async Port Scanner + InternetDB enrichment
Pure asyncio TCP connect scan. Optional Shodan InternetDB (free, no key).
"""
import asyncio
import socket
from typing import List, Dict

import httpx

from .. import logger


# ─────────────────────────────────────────────────────────────
#  Port list (top 1000 default, or common subset if smaller)
# ─────────────────────────────────────────────────────────────

TOP_PORTS_1000 = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 548, 554,
    587, 631, 636, 646, 873, 990, 993, 995, 1025, 1080, 1194, 1433, 1434,
    1521, 1701, 1723, 1755, 1812, 1813, 1900, 2000, 2049, 2082, 2083,
    2086, 2087, 2095, 2096, 2121, 2222, 2375, 2376, 2483, 2484, 3128,
    3260, 3268, 3306, 3389, 3478, 3690, 4000, 4443, 4505, 4506, 5000,
    5060, 5061, 5222, 5269, 5357, 5432, 5555, 5601, 5672, 5683, 5900,
    5938, 5984, 6000, 6379, 6443, 6667, 7001, 7002, 7077, 7443, 7474,
    8000, 8001, 8008, 8010, 8042, 8069, 8080, 8081, 8082, 8088, 8090,
    8091, 8118, 8123, 8140, 8161, 8181, 8200, 8222, 8300, 8332, 8333,
    8400, 8443, 8500, 8529, 8880, 8888, 8983, 9000, 9001, 9042, 9060,
    9080, 9090, 9091, 9092, 9100, 9160, 9200, 9300, 9418, 9443, 9600,
    9999, 10000, 10250, 10443, 11211, 15672, 16379, 27017, 27018, 28017,
    50000, 50070, 61616,
]


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ─────────────────────────────────────────────────────────────
#  Async TCP connect scan
# ─────────────────────────────────────────────────────────────

async def _try_connect(host: str, port: int, timeout: float) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Try to read a banner from the open port."""
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner
    except Exception:
        return ""


async def scan_host(host: str, ports: List[int], cfg) -> List[Dict]:
    sem = asyncio.Semaphore(cfg.scan.concurrency)
    open_ports: List[Dict] = []

    async def worker(port: int):
        async with sem:
            ok = await _try_connect(host, port, cfg.scan.timeout)
            if ok:
                banner = await _grab_banner(
                    host, port, cfg.ports.banner_timeout
                )
                open_ports.append({
                    "host": host,
                    "port": port,
                    "service": _service_name(port),
                    "banner": banner,
                })

    await asyncio.gather(*(worker(p) for p in ports))
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ─────────────────────────────────────────────────────────────
#  Shodan InternetDB — free, no key
# ─────────────────────────────────────────────────────────────

async def internetdb(ip: str) -> Dict:
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(url)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return {}


# ─────────────────────────────────────────────────────────────
#  Orchestrator
# ─────────────────────────────────────────────────────────────

async def scan(hosts: List[str], cfg, db) -> List[Dict]:
    logger.phase(2, "Port Scanning")

    all_results: List[Dict] = []
    ports = TOP_PORTS_1000[: cfg.ports.top_ports]

    for host in hosts:
        logger.sub(f"Scanning {host} ({len(ports)} ports)...")
        results = await scan_host(host, ports, cfg)

        for r in results:
            db.add_port(r["host"], r["port"], r["service"], r["banner"])

        logger.sub(f"{host}: {len(results)} open ports")
        all_results.extend(results)

        # Optional: enrich via InternetDB
        if cfg.ports.use_internetdb and results:
            try:
                ip = socket.gethostbyname(host)
                info = await internetdb(ip)
                if info.get("ports"):
                    logger.sub(
                        f"InternetDB says {ip} also has ports: "
                        f"{info['ports']}"
                    )
            except Exception:
                pass

    return all_results
