"""TCP Connect scanner using asyncio.open_connection."""
import asyncio
import time

from ..models import PortResult, PortState
from .base import BaseScanner


class ConnectScanner(BaseScanner):
    name = "connect"
    requires_root = False

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    async def scan(self, ip: str, port: int) -> PortResult:
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            elapsed = (time.monotonic() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortResult(
                port=port, protocol="tcp", state=PortState.OPEN,
                reason="syn-ack", response_time_ms=round(elapsed, 1),
            )
        except ConnectionRefusedError:
            return PortResult(
                port=port, protocol="tcp", state=PortState.CLOSED,
                reason="connection-refused",
            )
        except (asyncio.TimeoutError, TimeoutError):
            return PortResult(
                port=port, protocol="tcp", state=PortState.FILTERED,
                reason="timeout",
            )
        except OSError as e:
            return PortResult(
                port=port, protocol="tcp", state=PortState.FILTERED,
                reason=f"oserror: {e.__class__.__name__}",
            )
