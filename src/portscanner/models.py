"""Core data models for scan results."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class ScanType(Enum):
    CONNECT = "connect"
    SYN = "syn"
    UDP = "udp"


@dataclass
class PortResult:
    port: int
    protocol: str              # "tcp" or "udp"
    state: PortState
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    vuln_hints: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class HostResult:
    ip: str
    hostname: Optional[str] = None
    is_up: bool = False
    ports: List[PortResult] = field(default_factory=list)
    os_guess: Optional[str] = None


@dataclass
class ScanResult:
    targets: List[HostResult]
    scan_type: ScanType
    start_time: datetime
    end_time: Optional[datetime] = None
    command_line: str = ""
    total_ports_scanned: int = 0
    open_ports_found: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["scan_type"] = self.scan_type.value
        d["start_time"] = self.start_time.isoformat()
        d["end_time"] = self.end_time.isoformat() if self.end_time else None
        for host in d["targets"]:
            for port in host["ports"]:
                port["state"] = port["state"].value if isinstance(port["state"], PortState) else port["state"]
        return d

    @staticmethod
    def now() -> datetime:
        return datetime.now(timezone.utc)


def now() -> datetime:
    """Module-level UTC now() helper."""
    return datetime.now(timezone.utc)
