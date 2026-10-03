"""Configuration loading (YAML + CLI overrides)."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ScanConfig:
    type: str = "connect"              # connect | syn | udp
    ports: str = "top-1000"
    timeout: float = 2.0
    rate_limit: int = 500
    timing: str = "normal"
    max_concurrent: int = 200


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    methods: List[str] = field(default_factory=lambda: ["icmp", "tcp"])


@dataclass
class OutputConfig:
    formats: List[str] = field(default_factory=lambda: ["json", "html"])
    directory: str = "./reports"
    basename: str = "scan"


@dataclass
class LoggingConfig:
    level: str = "INFO"


@dataclass
class AppConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(path: Optional[str]) -> AppConfig:
    """Load YAML config; return defaults if path is None."""
    if not path:
        return AppConfig()

    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Config not found: {path}")

    raw: Dict[str, Any] = yaml.safe_load(p.read_text()) or {}

    cfg = AppConfig()
    if "scan" in raw:
        for k, v in raw["scan"].items():
            if hasattr(cfg.scan, k):
                setattr(cfg.scan, k, v)
    if "discovery" in raw:
        for k, v in raw["discovery"].items():
            if hasattr(cfg.discovery, k):
                setattr(cfg.discovery, k, v)
    if "output" in raw:
        for k, v in raw["output"].items():
            if hasattr(cfg.output, k):
                setattr(cfg.output, k, v)
    if "logging" in raw:
        for k, v in raw["logging"].items():
            if hasattr(cfg.logging, k):
                setattr(cfg.logging, k, v)
    return cfg
