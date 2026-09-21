"""
TryRecon — Logger
Colored console output with Rich.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def info(msg: str):
    console.print(f"[cyan][*][/cyan] {msg}")


def success(msg: str):
    console.print(f"[green][+][/green] {msg}")


def warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")


def error(msg: str):
    console.print(f"[red][-][/red] {msg}")


def debug(msg: str):
    console.print(f"[dim][.][/dim] {msg}")


def banner():
    text = """[bold cyan]
  _____          ____
 |_   _| __ _  _|  _ \\ ___  ___ ___  _ __
   | |  | '__| | |_) / _ \\/ __/ _ \\| '_ \\
   | |  | |    |  _ <  __/ (_| (_) | | | |
   |_|  |_|    |_| \\_\\___|\\___\\___/|_| |_|
[/bold cyan]
[dim]OSINT reconnaissance framework  •  v1.0.0[/dim]
"""
    console.print(text)


def phase(num: int, title: str):
    console.print(f"\n[bold magenta][Phase {num}][/bold magenta] "
                  f"[bold]{title}[/bold]")


def sub(msg: str):
    console.print(f"    [dim]└─[/dim] {msg}")


def subdomains_table(subs):
    table = Table(title="Subdomains")
    table.add_column("#", style="bold")
    table.add_column("Name", style="cyan")
    table.add_column("IP")
    table.add_column("Source")
    for i, s in enumerate(subs, 1):
        table.add_row(str(i), s.get("name", ""),
                      s.get("ip", "-"), s.get("source", "-"))
    console.print(table)


def ports_table(host: str, ports):
    table = Table(title=f"Open ports — {host}")
    table.add_column("Port", style="bold")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Banner", overflow="fold")
    for p in ports:
        table.add_row(
            str(p.get("port", "")),
            "[green]open[/green]",
            p.get("service", "-"),
            (p.get("banner", "") or "")[:80],
        )
    console.print(table)


def tech_table(host: str, techs):
    table = Table(title=f"Technologies — {host}")
    table.add_column("Name", style="bold cyan")
    table.add_column("Version")
    table.add_column("Category")
    for t in techs:
        table.add_row(t.get("name", ""), t.get("version", "-"),
                      t.get("category", "-"))
    console.print(table)


def emails_table(emails):
    table = Table(title="Emails")
    table.add_column("#", style="bold")
    table.add_column("Email", style="cyan")
    table.add_column("Source")
    table.add_column("Breaches", style="red")
    for i, e in enumerate(emails, 1):
        breaches = ", ".join(e.get("breaches", [])) or "-"
        table.add_row(str(i), e.get("email", ""),
                      e.get("source", "-"), breaches)
    console.print(table)


def phone_panel(result: dict):
    lines = []
    for k, v in result.items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v) if v else "-"
        lines.append(f"[bold]{k}[/bold]: {v}")
    console.print(Panel("\n".join(lines),
                        title="Phone Number OSINT",
                        border_style="cyan"))


def summary(findings: dict):
    table = Table(title="Scan Summary")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right", style="cyan")
    for k, v in findings.items():
        table.add_row(k, str(v))
    console.print(table)
