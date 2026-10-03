"""Baseline comparison between two JSON scan reports."""
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _open_ports(host: dict) -> Set[int]:
    return {p["port"] for p in host.get("ports", [])
            if p.get("state") == "open"}


def diff_scans(baseline_path: str, current_path: str) -> List[str]:
    """Return human-readable change list."""
    baseline = _load(baseline_path)
    current = _load(current_path)

    base_hosts: Dict[str, dict] = {h["ip"]: h for h in baseline["targets"]}
    curr_hosts: Dict[str, dict] = {h["ip"]: h for h in current["targets"]}

    changes: List[str] = []
    all_ips = sorted(set(base_hosts) | set(curr_hosts))

    for ip in all_ips:
        b = base_hosts.get(ip)
        c = curr_hosts.get(ip)

        if b and not c:
            changes.append(f"[REMOVED]   {ip} no longer present")
            continue
        if c and not b:
            changes.append(f"[ADDED]     {ip} new host")
            continue

        bp = _open_ports(b)
        cp = _open_ports(c)
        for p in sorted(cp - bp):
            changes.append(f"[NEW]       {ip}:{p} now open")
        for p in sorted(bp - cp):
            changes.append(f"[CLOSED]    {ip}:{p} no longer open")

    return changes or ["No changes detected."]
