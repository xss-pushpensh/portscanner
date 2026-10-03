"""Command-line interface."""
import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn, TextColumn,
                           TimeRemainingColumn)
from rich.table import Table

from . import __version__
from .compare import diff_scans
from .config import load_config
from .discovery import discover_hosts
from .engine import run_scan
from .models import PortState, ScanType
from .rate_limit import TIMING_TEMPLATES, RateLimiter
from .reporters import write_html, write_json
from .utils import is_root, parse_ports, parse_targets, guess_os_from_ttl

console = Console()
log = logging.getLogger("portscanner")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _banner() -> None:
    console.print(r"""[bold red]
 ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
 ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold red][dim]  Async Port Scanner  v{ver}  ·  XSS.PUSHPENSH[/dim]
""".format(ver=__version__))


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("targets", required=False)
@click.option("-p", "--ports", default="top-1000",
              help="Port spec: 22,80,443 | 1-1024 | top-100 | top-1000")
@click.option("-sT", "--connect", "scan_connect", is_flag=True,
              help="TCP Connect scan (default, no root)")
@click.option("-sS", "--syn", "scan_syn", is_flag=True,
              help="TCP SYN (stealth) scan — requires root + scapy")
@click.option("-sU", "--udp", "scan_udp", is_flag=True,
              help="UDP scan")
@click.option("-T", "--timing", default="normal",
              type=click.Choice(list(TIMING_TEMPLATES.keys())),
              help="Timing template")
@click.option("--rate", type=int, default=None,
              help="Custom rate limit (packets per second)")
@click.option("--timeout", type=float, default=None,
              help="Per-probe timeout in seconds")
@click.option("--max-concurrent", type=int, default=200,
              help="Max concurrent probes")
@click.option("-Pn", "--no-discovery", is_flag=True,
              help="Skip host discovery (treat all as up)")
@click.option("-oJ", "--json", "json_path", default=None,
              help="Write JSON report to path")
@click.option("-oH", "--html", "html_path", default=None,
              help="Write HTML report to path")
@click.option("--baseline", default=None, type=click.Path(),
              help="Compare current scan to this baseline JSON and exit")
@click.option("-c", "--config", "config_path", default=None,
              type=click.Path(), help="YAML config file")
@click.option("--no-banner", is_flag=True, help="Skip banner grabbing")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]))
@click.version_option(__version__, "-V", "--version")
def main(targets, ports, scan_connect, scan_syn, scan_udp, timing, rate,
         timeout, max_concurrent, no_discovery, json_path, html_path,
         baseline, config_path, no_banner, log_level):
    """Advanced Asynchronous Port Scanner — authorized testing only."""
    _setup_logging(log_level)
    _banner()

    if not targets:
        console.print("[red][!] Targets required. See `portscanner --help`.[/red]")
        sys.exit(2)

    # --- Baseline compare shortcut ---
    if baseline:
        if not json_path:
            console.print("[red][!] --baseline requires -oJ <current.json>[/red]")
            sys.exit(2)
        changes = diff_scans(baseline, json_path)
        console.print("[bold cyan]Changes vs baseline:[/bold cyan]")
        for line in changes:
            console.print(f"  {line}")
        return 0

    # --- Load config ---
    try:
        cfg = load_config(config_path)
    except FileNotFoundError as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)

    # --- Determine scan type ---
    if scan_syn:
        scan_type = ScanType.SYN
    elif scan_udp:
        scan_type = ScanType.UDP
    else:
        scan_type = ScanType.CONNECT

    # --- Privilege check for SYN ---
    if scan_type == ScanType.SYN and not is_root():
        console.print("[red][!] SYN scan requires root. Run with sudo.[/red]")
        sys.exit(1)

    # --- Timing ---
    tmpl = TIMING_TEMPLATES[timing]
    effective_rate = rate or tmpl.rate
    effective_timeout = timeout or tmpl.timeout

    # --- Targets & ports ---
    try:
        ips = parse_targets(targets)
    except ValueError as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)

    try:
        port_list = parse_ports(ports)
    except ValueError as e:
        console.print(f"[red][!] {e}[/red]")
        sys.exit(1)

    console.print(f"[cyan][*] Targets:[/cyan] {len(ips)} host(s)")
    console.print(f"[cyan][*] Ports:[/cyan]   {len(port_list)} port(s)")
    console.print(f"[cyan][*] Scan:[/cyan]    {scan_type.value} | "
                  f"rate={effective_rate}/s timeout={effective_timeout}s")

    # --- Host discovery ---
    if not no_discovery:
        console.print("[cyan][*] Running host discovery...[/cyan]")

        async def _discover():
            rl = RateLimiter(effective_rate)
            return await discover_hosts(ips, ["tcp"], effective_timeout,
                                        rl, max_concurrent)

        try:
            discovered = asyncio.run(_discover())
        except KeyboardInterrupt:
            console.print("[yellow][!] Interrupted[/yellow]")
            sys.exit(130)

        live = [h.ip for h in discovered if h.is_up]
        console.print(f"[green][+] {len(live)}/{len(ips)} host(s) up[/green]")
        if not live:
            console.print("[yellow][!] No live hosts — try -Pn to skip discovery[/yellow]")
            sys.exit(0)
        ips = live
    else:
        console.print("[dim][*] Skipping discovery (-Pn)[/dim]")

    # --- Scan ---
    total_probes = len(ips) * len(port_list)
    console.print(f"[cyan][*] Total probes:[/cyan] {total_probes}")

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TextColumn("ETA:"),
        TimeRemainingColumn(),
        console=console,
    )

    def _progress_cb(stage: str, done: int, total: int) -> None:
        progress.update(task_id, completed=done)

    with progress:
        task_id = progress.add_task("Scanning", total=total_probes)

        try:
            result = asyncio.run(run_scan(
                ips=ips,
                ports=port_list,
                scan_type=scan_type,
                timeout=effective_timeout,
                rate_limit=effective_rate,
                max_concurrent=max_concurrent,
                command_line=" ".join(sys.argv),
                do_banner=not no_banner,
                progress=_progress_cb,
            ))
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Scan interrupted[/yellow]")
            sys.exit(130)

    # --- OS fingerprinting ---
    try:
        async def _os_scan():
            for host in result.targets:
                if host.ports:
                    host.os_guess = await guess_os_from_ttl(host.ip)
        asyncio.run(_os_scan())
    except Exception:
        pass

    # --- Report to terminal ---
    _print_summary(result)

    # --- Files ---
    cfg_dir = Path(cfg.output.directory)
    json_out = json_path or str(cfg_dir / f"{cfg.output.basename}.json")
    html_out = html_path or str(cfg_dir / f"{cfg.output.basename}.html")

    try:
        if "json" in cfg.output.formats or json_path:
            write_json(result, json_out)
            console.print(f"[green][+] JSON:[/green] {json_out}")
        if "html" in cfg.output.formats or html_path:
            write_html(result, html_out)
            console.print(f"[green][+] HTML:[/green] {html_out}")
    except Exception as e:
        console.print(f"[red][!] Report write failed: {e}[/red]")

    return 0


def _print_summary(result) -> None:
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.text import Text

    from .utils import severity_from_hints

    # ------- Top stats panel -------
    duration = round((result.end_time - result.start_time).total_seconds(), 2)
    stats = Text()
    stats.append("  Hosts Scanned: ", style="bold white")
    stats.append(f"{len(result.targets)}", style="bold cyan")
    stats.append("   ·   Ports Probed: ", style="bold white")
    stats.append(f"{result.total_ports_scanned}", style="bold cyan")
    stats.append("   ·   Open Ports: ", style="bold white")
    stats.append(f"{result.open_ports_found}", style="bold green")
    stats.append("   ·   Duration: ", style="bold white")
    stats.append(f"{duration}s", style="bold yellow")

    console.print()
    console.print(Panel(
        stats,
        title="[bold magenta]\U0001F4E1  SCAN SUMMARY[/bold magenta]",
        subtitle="[dim]XSS.PUSHPENSH \u00b7 v" + __import__("portscanner").__version__ + "[/dim]",
        border_style="magenta",
        padding=(1, 2),
    ))

    # ------- Per-host tables -------
    for host in result.targets:
        open_ports = [p for p in host.ports if p.state == PortState.OPEN]
        if not open_ports:
            continue

        os_line = f"   [dim]OS: {host.os_guess}[/dim]" if host.os_guess else ""
        console.print()
        console.print(Rule(
            f"[bold green]  {host.ip}  [/bold green]"
            f"[dim]\u00b7 {len(open_ports)} open port(s)[/dim]" + os_line,
            style="green",
        ))

        table = Table(
            show_header=True,
            header_style="bold white on #2d333b",
            border_style="grey37",
            row_styles=["", "on #161b22"],
            expand=True,
            padding=(0, 1),
        )
        table.add_column("Port",       style="bold cyan",    justify="right", width=6)
        table.add_column("Proto",      style="dim",           justify="center", width=5)
        table.add_column("State",      justify="center",      width=7)
        table.add_column("Service",    style="bold white",    width=10)
        table.add_column("Version",    style="yellow",        width=22, overflow="fold")
        table.add_column("Severity",   justify="center",      width=9)
        table.add_column("RTT",        style="dim cyan",      justify="right", width=7)
        table.add_column("Banner",     style="dim",           overflow="fold", width=32)
        table.add_column("CVE",        justify="left",        overflow="fold", width=28)

        sev_style = {
            "CRITICAL": "[bold white on red] CRITICAL [/bold white on red]",
            "HIGH":     "[bold red] HIGH [/bold red]",
            "MEDIUM":   "[bold yellow] MEDIUM [/bold yellow]",
            "LOW":      "[cyan] LOW [/cyan]",
            "—":        "[dim]\u2014[/dim]",
        }

        for p in open_ports:
            sev = severity_from_hints(p.vuln_hints)
            state_str = ("[bold green]\u25cf open[/bold green]"
                         if p.state == PortState.OPEN
                         else f"[yellow]\u25cf {p.state.value}[/yellow]")
            rt = f"{p.response_time_ms}ms" if p.response_time_ms else "\u2014"

            # Banner snippet (first line, trimmed)
            banner_snip = "\u2014"
            if p.banner:
                first = p.banner.splitlines()[0].strip() if p.banner else ""
                banner_snip = (first[:60] + "\u2026") if len(first) > 60 else first
                if not banner_snip:
                    banner_snip = "\u2014"

            # CVE line (compact)
            cve_txt = "\u2014"
            if p.vuln_hints:
                cves = [h.split(" \u2014 ")[0] for h in p.vuln_hints]
                cve_txt = ", ".join(cves[:2])

            table.add_row(
                str(p.port),
                p.protocol,
                state_str,
                p.service or "\u2014",
                p.version or "\u2014",
                sev_style.get(sev, sev),
                rt,
                banner_snip,
                cve_txt,
            )

        console.print(table)

        # ------- Detailed vulnerability block -------
        vulnerable = [p for p in open_ports if p.vuln_hints]
        if vulnerable:
            console.print()
            console.print("[bold red]  \u26a0  Vulnerability Details[/bold red]")
            for p in vulnerable:
                console.print(f"    [bold yellow]\u203a[/bold yellow] "
                              f"[cyan]{host.ip}:{p.port}[/cyan] "
                              f"[dim]({p.service or '?'} {p.version or ''})[/dim]")
                for h in p.vuln_hints:
                    console.print(f"       [red]\u2022[/red] {h}")

    # ------- Bottom line -------
    console.print()
    if result.open_ports_found == 0:
        console.print("[yellow]  \u24d8  No open ports detected on any host.[/yellow]")
        console.print("[dim]     Tip: start some services (ssh, apache2, "
                      "python3 -m http.server) to see results.[/dim]")
    else:
        console.print(f"[bold green]  \u2713  Scan complete.[/bold green] "
                      f"[white]{result.open_ports_found} open port(s) "
                      f"across {len(result.targets)} host(s).[/white]")
    console.print()


if __name__ == "__main__":
    sys.exit(main())
