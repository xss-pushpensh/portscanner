"""UDP scanner — best-effort open|filtered detection."""
import asyncio
import socket
import time

from ..models import PortResult, PortState
from .base import BaseScanner


class UdpScanner(BaseScanner):
    name = "udp"
    requires_root = False

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def scan(self, ip: str, port: int) -> PortResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._blocking_scan, ip, port)

    def _blocking_scan(self, ip: str, port: int) -> PortResult:
        start = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b"\x00", (ip, port))
            try:
                data, _ = sock.recvfrom(4096)
                elapsed = (time.monotonic() - start) * 1000
                return PortResult(
                    port=port, protocol="udp", state=PortState.OPEN,
                    banner=data.hex()[:120] if data else None,
                    reason="data-received",
                    response_time_ms=round(elapsed, 1),
                )
            except socket.timeout:
                return PortResult(
                    port=port, protocol="udp", state=PortState.OPEN_FILTERED,
                    reason="no-response",
                )
        except ConnectionRefusedError:
            return PortResult(
                port=port, protocol="udp", state=PortState.CLOSED,
                reason="icmp-port-unreachable",
            )
        except OSError as e:
            return PortResult(
                port=port, protocol="udp", state=PortState.UNKNOWN,
                reason=f"oserror: {e.__class__.__name__}",
            )
        finally:
            sock.close()
