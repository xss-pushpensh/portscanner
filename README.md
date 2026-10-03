<div align="center">

# Advanced Asynchronous Port Scanner

**A professional-grade, asyncio-powered network reconnaissance tool for authorized security testing.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Async](https://img.shields.io/badge/asyncio-concurrent-2ea043)](https://docs.python.org/3/library/asyncio.html)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-ff7b72)](https://scapy.net/)
[![Code style](https://img.shields.io/badge/code%20style-pep8-blue)](https://peps.python.org/pep-0008/)
[![Tests](https://img.shields.io/badge/tests-pytest-brightgreen)](https://pytest.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](.)

**XSS.PUSHPENSH · v1.0.0 · For Authorized Testing Only**

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Why This Project Exists](#-why-this-project-exists)
- [Feature Highlights](#-feature-highlights)
- [Architecture Deep Dive](#-architecture-deep-dive)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Scan Techniques Explained](#-scan-techniques-explained)
- [Target Specification Formats](#-target-specification-formats)
- [Port Specification Formats](#-port-specification-formats)
- [Timing Templates & Rate Limiting](#-timing-templates--rate-limiting)
- [Banner Grabbing & Service Detection](#-banner-grabbing--service-detection)
- [Vulnerability Hint Engine](#-vulnerability-hint-engine)
- [Host Discovery](#-host-discovery)
- [Baseline Comparison & Diff Mode](#-baseline-comparison--diff-mode)
- [Configuration System](#-configuration-system)
- [Reporting Formats](#-reporting-formats)
- [Command-Line Reference](#-command-line-reference)
- [Real-World Workflows](#-real-world-workflows)
- [Testing](#-testing)
- [Performance Tuning](#-performance-tuning)
- [Troubleshooting](#-troubleshooting)
- [Project Structure](#-project-structure)
- [Design Decisions](#-design-decisions)
- [Interview Preparation](#-interview-preparation)
- [Ethical & Legal Notice](#-ethical--legal-notice)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**Advanced Asynchronous Port Scanner** is a production-quality network reconnaissance tool built in pure Python 3.10+. It performs concurrent host discovery, multi-technique port scanning, service fingerprinting, and vulnerability hinting — all through a clean, modern CLI with beautiful terminal output and professional HTML/JSON reporting.

Designed as a **learning-grade + portfolio-grade** project, it demonstrates deep understanding of:

- **TCP/IP networking** — three-way handshake, half-open scanning, UDP semantics
- **Asynchronous programming** — `asyncio`, coroutines, semaphores, event loops
- **Raw packet crafting** — Scapy-based SYN scanning
- **Software architecture** — modular design, separation of concerns, type hints
- **Security reconnaissance** — port scanning, banner grabbing, CVE mapping
- **Professional CLI design** — Click framework, Rich terminal UI
- **Report generation** — Jinja2 templating, JSON serialization

Whether you're a penetration tester, red teamer, security researcher, or student — this tool gives you a clean, auditable codebase to learn from and extend.

---

## 💡 Why This Project Exists

Port scanners are the **first step in every security engagement**. Before you can exploit anything, you must know what's running. Commercial tools like Nmap are excellent — but opaque. Building your own teaches you:

1. **How TCP handshakes really work** — not from a textbook, but from live sockets
2. **Why SYN scans need root** — raw socket access is a Linux kernel privilege
3. **How async beats threads** — 10,000 concurrent connections on one event loop
4. **What makes services identifiable** — banners are fingerprints
5. **Why rate limiting matters** — a fast scanner is a DoS weapon

This project doesn't try to replace Nmap. It **teaches you to think like the tools you use**.

---

## ✨ Feature Highlights

### 🔥 Core Engine
- **Fully asynchronous** — `asyncio` based, thousands of concurrent probes
- **Semaphore-limited concurrency** — safe parallelism without overwhelming your own machine
- **Token-bucket rate limiter** — precise control over packets per second
- **Graceful interrupt handling** — `Ctrl+C` saves partial results

### 🎯 Scan Techniques
- **TCP Connect Scan** — full three-way handshake, no root required
- **TCP SYN Scan** — half-open "stealth" scan via Scapy raw sockets (root)
- **UDP Scan** — best-effort UDP probing with ICMP interpretation

### 🧠 Intelligence
- **Host discovery** — ICMP echo + TCP ping on common ports
- **Banner grabbing** — protocol-aware probes (HTTP, FTP, SSH, SMTP)
- **Service detection** — regex-based fingerprinting of ~15 services
- **Version extraction** — pull exact software versions from banners
- **CVE hint engine** — map known-vulnerable versions to CVEs
- **OS fingerprinting** — best-effort TTL-based guess

### 📊 Reporting
- **Rich terminal UI** — color-coded tables, progress bars, ETA
- **JSON reports** — structured output for automation
- **HTML reports** — beautiful, printable, shareable
- **Baseline diff** — track changes between scans
- **Summary cards** — hosts, ports, duration at a glance

### ⚙️ Usability
- **YAML config files** — declarative scan profiles
- **6 timing templates** — from `paranoid` to `insane`
- **Flexible targets** — IP, hostname, CIDR, range, file
- **Flexible ports** — top-100, top-1000, ranges, custom lists
- **Full type hints** — modern Python, IDE-friendly

---

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `models.py` | Typed dataclasses — `PortResult`, `HostResult`, `ScanResult` |
| `config.py` | YAML config loader with dataclass-based defaults |
| `utils.py` | Target/port parsers, OS fingerprint helper, privilege check |
| `rate_limit.py` | Async token bucket + timing templates |
| `discovery.py` | Host liveness detection (ICMP + TCP) |
| `scanner/base.py` | Abstract scanner interface |
| `scanner/connect.py` | Async TCP Connect scanner |
| `scanner/syn.py` | Scapy-based raw SYN scanner |
| `scanner/udp.py` | UDP scanner with ICMP interpretation |
| `banner.py` | Protocol-aware banner grabbing |
| `vulnhints.py` | Local CVE hint database |
| `engine.py` | Async orchestration of scan workflow |
| `compare.py` | Baseline diff between two JSON reports |
| `reporters/json_reporter.py` | JSON serialization |
| `reporters/html_reporter.py` | Jinja2-based HTML rendering |
| `cli.py` | Click CLI, Rich UI, entry point |

### Install From Source

# Clone the repository
git clone https://github.com/xss-pushpensh/portscanner.git
cd portscanner

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate           # Windows

# Install in editable mode
pip install -e .

# Optional: install test dependencies
pip install -e ".[dev]"

# Verification 
portscanner --version
portscanner --help

Localhost — First Scan
bash

portscanner 127.0.0.1

## Full Port Range
# bash

portscanner 127.0.0.1 -p 1-65535

## Scan With Reports
# bash

portscanner 192.168.73.128 \
    -p top-1000 \
    -oJ reports/scan.json \
    -oH reports/scan.html

## SYN Stealth Scan (Needs Root)
# bash

sudo $(which portscanner) 192.168.73.128 -sS -p top-1000

UDP Scan
bash

sudo $(which portscanner) 127.0.0.1 -sU -p 53,123,161
