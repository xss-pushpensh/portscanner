"""Asynchronous scanner orchestration."""
import asyncio
import sys
from typing import Callable, List, Optional

from .banner import grab_banner, parse_banner
from .models import (HostResult, PortResult, PortState, ScanResult,
                     ScanType, now)
from .rate_limit import RateLimiter
from .scanner import ConnectScanner, SynScanner, UdpScanner
from .vulnhints import get_vuln_hints


def _make_scanner(scan_type: ScanType, timeout: float):
    if scan_type == ScanType.CONNECT:
        return ConnectScanner(timeout=timeout)
    if scan_type == ScanType.SYN:
        return SynScanner(timeout=timeout)
    if scan_type == ScanType.UDP:
        return UdpScanner(timeout=timeout)
    raise ValueError(f"Unknown scan type: {scan_type}")


async def run_scan(
    ips: List[str],
    ports: List[int],
    scan_type: ScanType,
    timeout: float,
    rate_limit: int,
    max_concurrent: int,
    command_line: str,
    do_banner: bool = True,
    progress: Optional[Callable[[str, int, int], None]] = None,
) -> ScanResult:
    """Run the full scan. `progress` is called as (stage, done, total)."""

    scanner = _make_scanner(scan_type, timeout)
    rate_limiter = RateLimiter(rate_limit)
    sem = asyncio.Semaphore(max_concurrent)

    started = now()
    result = ScanResult(
        targets=[], scan_type=scan_type, start_time=started,
        command_line=command_line,
    )

    total = len(ips) * len(ports)
    done = 0
    lock = asyncio.Lock()

    async def _scan_one(ip: str, port: int) -> PortResult:
        nonlocal done
        async with sem:
            await rate_limiter.acquire()
            pr = await scanner.scan(ip, port)

            # Only grab banner for OPEN TCP ports
            if do_banner and pr.state == PortState.OPEN and pr.protocol == "tcp":
                try:
                    banner = await grab_banner(ip, port, timeout=timeout + 1)
                    if banner:
                        pr.banner = banner
                        svc, ver = parse_banner(banner, port)
                        pr.service = svc
                        pr.version = ver or None
                        pr.vuln_hints = get_vuln_hints(svc, ver, banner)
                except Exception:
                    pass

            async with lock:
                done += 1
                if progress:
                    progress("scan", done, total)
            return pr

    # Group tasks per host
    hosts: List[HostResult] = []
    for ip in ips:
        hosts.append(HostResult(ip=ip, is_up=True))

    tasks = []
    for host in hosts:
        for port in ports:
            tasks.append((host, asyncio.create_task(_scan_one(host.ip, port))))

    # Collect
    for host, task in tasks:
        try:
            pr = await task
            host.ports.append(pr)
        except Exception:
            pass

    # Sort ports per host
    for host in hosts:
        host.ports.sort(key=lambda p: p.port)

    result.targets = hosts
    result.total_ports_scanned = total
    result.open_ports_found = sum(
        1 for h in hosts for p in h.ports if p.state == PortState.OPEN
    )
    result.end_time = now()
    return result
