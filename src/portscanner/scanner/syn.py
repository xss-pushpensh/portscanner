"""TCP SYN (half-open) scanner using Scapy raw sockets."""
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

from ..models import PortResult, PortState
from .base import BaseScanner

try:
    from scapy.all import IP, TCP, send, sr1, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


_executor = ThreadPoolExecutor(max_workers=16)


def _sync_syn_scan(ip: str, port: int, timeout: float) -> PortResult:
    """Blocking SYN probe — runs inside thread pool."""
    conf.verb = 0
    start = time.monotonic()
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
    except Exception as e:
        return PortResult(
            port=port, protocol="tcp", state=PortState.UNKNOWN,
            reason=f"scapy-error: {e.__class__.__name__}",
        )

    elapsed = (time.monotonic() - start) * 1000

    if resp is None:
        return PortResult(
            port=port, protocol="tcp", state=PortState.FILTERED,
            reason="no-response", response_time_ms=round(elapsed, 1),
        )

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags & 0x12 == 0x12:        # SYN-ACK
            try:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
            except Exception:
                pass
            return PortResult(
                port=port, protocol="tcp", state=PortState.OPEN,
                reason="syn-ack", response_time_ms=round(elapsed, 1),
            )
        if flags & 0x14 == 0x14:        # RST-ACK
            return PortResult(
                port=port, protocol="tcp", state=PortState.CLOSED,
                reason="rst-ack", response_time_ms=round(elapsed, 1),
            )

    if resp.haslayer("ICMP"):
        return PortResult(
            port=port, protocol="tcp", state=PortState.FILTERED,
            reason="icmp-unreachable",
        )

    return PortResult(port=port, protocol="tcp", state=PortState.UNKNOWN)


class SynScanner(BaseScanner):
    name = "syn"
    requires_root = True

    def __init__(self, timeout: float = 2.0):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not installed. Run: pip install scapy")
        self.timeout = timeout

    async def scan(self, ip: str, port: int) -> PortResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            _executor, _sync_syn_scan, ip, port, self.timeout
        )
