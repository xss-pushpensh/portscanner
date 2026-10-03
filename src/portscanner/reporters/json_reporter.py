"""JSON report writer."""
import json
from pathlib import Path

from ..models import ScanResult


def write_json(result: ScanResult, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
