"""Base scanner interface."""
from abc import ABC, abstractmethod

from ..models import PortResult


class BaseScanner(ABC):
    """All scan engines implement this interface."""

    name: str = "base"
    requires_root: bool = False

    @abstractmethod
    async def scan(self, ip: str, port: int) -> PortResult:
        """Scan a single (ip, port) and return a PortResult."""
        ...
