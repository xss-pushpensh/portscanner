"""Banner grabbing and service/version extraction."""
import asyncio
import re
from typing import Optional, Tuple


HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: PortScanner/1.0\r\n\r\n"


async def grab_banner(ip: str, port: int, timeout: float = 3.0
                      ) -> Optional[str]:
    """Return banner string or None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return None

    try:
        # Some services need a probe
        if port in (80, 8080, 8000, 8888):
            writer.write(HTTP_PROBE % ip.encode())
        elif port in (443, 8443):
            # TLS — skip HTTP probe; attempt passive read
            pass
        else:
            writer.write(b"\r\n")
        try:
            await writer.drain()
        except Exception:
            pass

        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        except (asyncio.TimeoutError, TimeoutError):
            data = b""

        return data.decode("utf-8", errors="replace").strip() if data else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def parse_banner(banner: str, port: int) -> Tuple[str, str]:
    """Extract (service, version) from a banner string."""
    if not banner:
        return "unknown", ""

    b = banner

    # SSH
    m = re.search(r"SSH-[\d.]+-([^\s\r\n]+)", b)
    if m:
        return "ssh", m.group(1)

    # HTTP Server header
    m = re.search(r"Server:\s*([^\r\n]+)", b, re.IGNORECASE)
    if m:
        svc = "https" if port in (443, 8443) else "http"
        return svc, m.group(1).strip()

    # FTP / SMTP greeting
    m = re.match(r"220[ -](.+)", b)
    if m:
        if port in (25, 465, 587):
            return "smtp", m.group(1).strip()
        return "ftp", m.group(1).strip()

    # MySQL
    if "mysql" in b.lower():
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", b)
        return "mysql", m.group(1) if m else ""

    # PostgreSQL
    if "postgres" in b.lower():
        return "postgresql", ""

    # Redis
    if b.startswith("-ERR") or b.startswith("+PONG") or b.startswith("$"):
        return "redis", ""

    # MongoDB
    if "mongodb" in b.lower() or "ismaster" in b.lower():
        return "mongodb", ""

    return "unknown", ""
