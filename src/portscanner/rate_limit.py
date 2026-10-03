"""Async token-bucket rate limiter + timing templates."""
import asyncio
import time
from dataclasses import dataclass


@dataclass
class TimingTemplate:
    name: str
    rate: int          # packets per second
    timeout: float     # per-probe timeout seconds


TIMING_TEMPLATES = {
    "paranoid":   TimingTemplate("paranoid",     5,    5.0),
    "sneaky":     TimingTemplate("sneaky",      20,    3.0),
    "polite":     TimingTemplate("polite",     100,    2.0),
    "normal":     TimingTemplate("normal",     500,    1.5),
    "aggressive": TimingTemplate("aggressive", 1500,   0.8),
    "insane":     TimingTemplate("insane",     5000,   0.3),
}


class RateLimiter:
    """Token-bucket rate limiter safe for concurrent async use."""

    def __init__(self, rate: int):
        if rate <= 0:
            raise ValueError("Rate must be positive")
        self.rate = float(rate)
        self.tokens = float(rate)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last = now

            if self.tokens < 1.0:
                wait = (1.0 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0
