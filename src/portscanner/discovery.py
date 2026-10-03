"""Host discovery: ICMP echo + TCP ping."""
import asyncio
from typing import List

from .models import HostResult
from .rate_limit import RateLimiter


TCP_PING_PORTS = [80, 443, 22, 445, 3389, 8080]


async def _tcp_ping(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (ConnectionRefusedError,):
        # Host answered with RST — still means host is alive
        return True
    except (asyncio.TimeoutError, TimeoutError, OSError):
        return False


async def _icmp_ping(ip: str, timeout: float) -> bool:
    """Best-effort ICMP via scapy — non-root returns False."""
    try:
        from scapy.all import IP, ICMP, sr1, conf
    except ImportError:
        return False
    conf.verb = 0

    def _probe():
        try:
            return sr1(IP(dst=ip) / ICMP(), timeout=timeout, verbose=0) is not None
        except Exception:
            return False

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _probe)


async def is_host_up(ip: str, methods: List[str], timeout: float,
                     rate_limiter: RateLimiter) -> HostResult:
    host = HostResult(ip=ip)
    for method in methods:
        await rate_limiter.acquire()
        if method == "icmp":
            if await _icmp_ping(ip, timeout):
                host.is_up = True
                return host
        elif method == "tcp":
            for p in TCP_PING_PORTS:
                await rate_limiter.acquire()
                if await _tcp_ping(ip, p, timeout):
                    host.is_up = True
                    return host
    return host


async def discover_hosts(ips: List[str], methods: List[str], timeout: float,
                         rate_limiter: RateLimiter,
                         max_concurrent: int) -> List[HostResult]:
    sem = asyncio.Semaphore(max_concurrent)

    async def _one(ip: str) -> HostResult:
        async with sem:
            return await is_host_up(ip, methods, timeout, rate_limiter)

    return await asyncio.gather(*(_one(ip) for ip in ips))
