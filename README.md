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

## 🏗️ Architecture Deep Dive

### High-Level Pipeline
┌──────────────────────────────────────────────────────────────┐
│ CLI (Click) │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Config Loader (YAML) │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Target Parser ─► IP / CIDR / Range / Hostname / File │
│ Port Parser ─► top-100 / top-1000 / range / list │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Host Discovery (ICMP + TCP ping) │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Scan Engine (asyncio) │
│ ├─ Semaphore (max_concurrent) │
│ ├─ RateLimiter (token bucket) │
│ ├─ ConnectScanner / SynScanner / UdpScanner │
│ └─ Banner grabber (for open TCP ports) │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Vulnerability Hint Engine │
│ (local CVE DB — no online lookup) │
└───────────────────────────┬──────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────┐
│ Reporters │
│ ├─ Rich terminal (live progress + summary) │
│ ├─ JSON writer │
│ └─ HTML writer (Jinja2 template) │
└──────────────────────────────────────────────────────────────┘


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

### Async Concurrency Model

```python
# Simplified view of the concurrency core
sem = asyncio.Semaphore(max_concurrent)
rate = RateLimiter(rate_limit)

async def scan_one(ip, port):
    async with sem:                     # Limit active tasks
        await rate.acquire()            # Throttle requests
        return await scanner.scan(ip, port)

tasks = [scan_one(ip, p) for ip in ips for p in ports]
results = await asyncio.gather(*tasks)
Why this beats threads:

    asyncio.Semaphore is far lighter than thread locks

    10,000 pending coroutines cost ~10 MB; 10,000 threads cost ~80 GB

    The GIL doesn't bottleneck I/O-bound coroutines

📦 Installation
Prerequisites
Requirement	Version	Notes
Python	3.10+	Modern asyncio features required
pip	Latest	Bundled with modern Python
OS	Linux / macOS / Windows	Kali Linux recommended for full features
Root	Optional	Required for SYN scan only
Install From Source
bash

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

Verify Installation
bash

portscanner --version
portscanner --help

You should see the ASCII banner and full CLI help.
Dependencies
Library	Purpose
scapy	Raw packet crafting for SYN/UDP scans
aiofiles	Async file I/O
rich	Beautiful terminal UI
pyyaml	YAML config support
click	CLI framework
jinja2	HTML report templating
🚀 Quick Start
Localhost — First Scan
bash

portscanner 127.0.0.1

Full Port Range
bash

portscanner 127.0.0.1 -p 1-65535

Scan With Reports
bash

portscanner 192.168.73.128 \
    -p top-1000 \
    -oJ reports/scan.json \
    -oH reports/scan.html

SYN Stealth Scan (Needs Root)
bash

sudo $(which portscanner) 192.168.73.128 -sS -p top-1000

UDP Scan
bash

sudo $(which portscanner) 127.0.0.1 -sU -p 53,123,161

📖 Usage Guide
Basic Syntax
bash

portscanner [TARGETS] [OPTIONS]

Common Examples
1. Fast localhost check
bash

portscanner 127.0.0.1 -p top-100

2. Deep scan of a single host
bash

portscanner 192.168.1.100 -p 1-65535 -T aggressive

3. Full subnet sweep
bash

portscanner 192.168.1.0/24 -p 22,80,443,8080

4. IP range
bash

portscanner 192.168.1.1-50 -p top-1000

5. Multiple targets from file
bash

portscanner targets.txt -p 22,80,443

6. Domain scan
bash

portscanner scanme.nmap.org -p top-1000

7. Skip host discovery
bash

portscanner 192.168.1.1 -Pn -p top-100

8. Stealth scan with custom rate
bash

sudo $(which portscanner) 10.0.0.5 -sS --rate 100 -p 1-1024

9. With config file
bash

portscanner 192.168.1.0/24 -c config/default.yaml

10. Compare to baseline
bash

portscanner 192.168.1.1 -p top-100 -oJ baseline.json
# (wait for environment to change)
portscanner 192.168.1.1 -p top-100 -oJ current.json
portscanner --baseline baseline.json -oJ current.json

🔬 Scan Techniques Explained
TCP Connect Scan (-sT)

Default technique. Uses the OS socket API to perform a complete three-way handshake.
text

Client                  Server
   │  ──── SYN ────────▶  │
   │  ◀─── SYN-ACK ─────  │  → OPEN
   │  ──── ACK ────────▶  │
   │                       │
   │  ──── SYN ────────▶  │
   │  ◀─── RST-ACK ─────  │  → CLOSED

Pros: Works without root; reliable across all platforms.
Cons: Loud (target's app logs record the full connection); slower per port.
TCP SYN Scan (-sS)

Half-open "stealth" scan. Crafts raw SYN packets with Scapy — never completes handshake.
text

Client                  Server
   │  ──── SYN ────────▶  │
   │  ◀─── SYN-ACK ─────  │  → OPEN
   │  ──── RST ────────▶  │  (we abort)
   │                       │
   │  ◀─── RST-ACK ─────  │  → CLOSED
   │                       │
   │   (no response)       │  → FILTERED

Pros: Stealthier; faster per port; distinguishes closed vs filtered.
Cons: Requires root; Scapy not fully thread-safe (uses thread pool).
UDP Scan (-sU)

Connectionless probe — best-effort inference from ICMP errors.
text

Probe → Send UDP datagram
Response → ICMP port-unreachable → CLOSED
Response → ICMP unreachable      → FILTERED
Response → any UDP data          → OPEN
Timeout  → after retries          → OPEN|FILTERED

Pros: Discovers DNS, SNMP, NTP, DHCP, TFTP.
Cons: Inherently unreliable; slow; many services ignore empty probes.
🎯 Target Specification Formats
Format	Example	Notes
Single IP	192.168.1.1	
CIDR block	192.168.1.0/24	254 hosts
IP range	192.168.1.1-50	Last-octet range
Hostname	example.com	Resolved to IP
File	targets.txt	One target per line
Comma list	a.com,b.com,10.0.0.5	Mixed
Targets File Format
text

# Lines starting with # are comments
192.168.1.1
192.168.1.0/24
192.168.1.50-100
example.com

🔢 Port Specification Formats
Format	Example	Meaning
Single port	80	Just port 80
List	22,80,443	Three specific ports
Range	1-1024	All ports 1 to 1024
Mixed	1-100,3306,5432	Range plus singles
Top 100	top-100	100 most common
Top 1000	top-1000	1000 most common (default)
Full range	1-65535	Every port
⏱️ Timing Templates & Rate Limiting

Inspired by Nmap's -T flag. Each template controls rate (packets/second) and timeout (seconds).
Template	Rate	Timeout	Use Case
paranoid	5/s	5.0s	IDS evasion
sneaky	20/s	3.0s	External stealth
polite	100/s	2.0s	Production networks
normal	500/s	1.5s	Default
aggressive	1500/s	0.8s	Fast internal
insane	5000/s	0.3s	Local lab only

Override with --rate N or --timeout S:
bash

portscanner 10.0.0.5 -T polite --rate 50 --timeout 3.0

Token Bucket Algorithm
python

class RateLimiter:
    async def acquire(self):
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens < 1.0:
                await asyncio.sleep((1.0 - self.tokens) / self.rate)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0

Precise, fair, and safe across thousands of concurrent tasks.
🏷️ Banner Grabbing & Service Detection

After a TCP port is confirmed open, the scanner attempts to read the service banner.
Passive Read

Many services greet you immediately:
Service	Example Banner
SSH	SSH-2.0-OpenSSH_8.2p1 Ubuntu
FTP	220 (vsFTPd 3.0.3)
SMTP	220 mail.example.com ESMTP Postfix
Active Probe

HTTP servers stay silent until asked:
http

HEAD / HTTP/1.0
Host: target
User-Agent: PortScanner/1.0

Response's Server: header reveals the stack:
http

HTTP/1.1 200 OK
Server: Apache/2.4.49 (Debian)

Fingerprinting Table
Service	Pattern	Extracted
SSH	SSH-[\d.]+-(.+)	Full version
HTTP	Server:\s*(.+)	Web server + version
FTP/SMTP	220[ -](.+)	Server greeting
MySQL	mysql in body	Version number
Redis	-ERR or +PONG	Detected
MongoDB	ismaster in body	Detected
🛡️ Vulnerability Hint Engine

The tool maintains a local CVE hint database — no online lookups, works air-gapped.
Fingerprint	CVE	Severity
Apache/2.4.49	CVE-2021-41773 — Path traversal + RCE	CRITICAL
Apache/2.4.50	CVE-2021-42013 — Path traversal + RCE	CRITICAL
OpenSSH < 7.4	CVE-2016-0777 — Roaming key leak	MEDIUM
vsFTPd 2.3.4	CVE-2011-2523 — Backdoor	CRITICAL
nginx 1.20.0 / 1.21.0	CVE-2021-23017 — Resolver off-by-one	HIGH
ProFTPD 1.3.3c	CVE-2010-4221 — Backdoor	CRITICAL
Why Local?

    ✅ Works air-gapped

    ✅ No API rate limits

    ✅ No dependency on NVD uptime

    ✅ Controlled false-positive rate

This is not a vulnerability scanner — it's a hint engine to guide manual verification.
🛰️ Host Discovery

Before scanning ports, the tool checks which hosts are alive. Saves enormous time on large ranges.
Methods

    ICMP Echo (via Scapy) — classic ping

    TCP Ping — SYN to ports 80, 443, 22, 445, 3389, 8080

A host is "up" if any method succeeds.
Skip Discovery

Some hosts block ICMP (Windows firewall by default). Skip with -Pn:
bash

portscanner 192.168.1.1 -Pn -p top-100

📊 Baseline Comparison & Diff Mode

Track changes across scans — critical for continuous monitoring.
Workflow
bash

# Scan 1 — baseline
portscanner 10.0.0.0/24 -p top-100 -oJ baseline.json

# ... wait some time (deployments, patches, new hosts)...

# Scan 2 — current
portscanner 10.0.0.0/24 -p top-100 -oJ current.json

# Diff
portscanner --baseline baseline.json -oJ current.json

Sample Output
text

Changes vs baseline:
  [NEW]       10.0.0.5:8080 now open
  [NEW]       10.0.0.12:22 now open
  [CLOSED]    10.0.0.5:3306 no longer open
  [ADDED]     10.0.0.20 new host
  [REMOVED]   10.0.0.99 no longer present

Cron Integration
cron

0 2 * * * cd /opt/portscanner && \
  python3 -m portscanner 10.0.0.0/24 -p top-100 -Pn -oJ reports/nightly.json

⚙️ Configuration System

Support declarative YAML profiles merged with CLI overrides.
config/default.yaml
yaml

scan:
  type: connect          # connect | syn | udp
  ports: "top-1000"
  timeout: 2.0
  rate_limit: 500
  timing: normal
  max_concurrent: 200

discovery:
  enabled: true
  methods: ["icmp", "tcp"]

output:
  formats: ["json", "html"]
  directory: "./reports"
  basename: "scan"

logging:
  level: INFO

Usage
bash

portscanner 192.168.1.0/24 -c config/default.yaml

CLI flags override config values — config provides the baseline.
📄 Reporting Formats
1. JSON Report

Structured, machine-readable output for SIEM/ticketing integration.
json

{
  "scan_type": "connect",
  "start_time": "2026-10-03T12:00:00+00:00",
  "end_time": "2026-10-03T12:00:45+00:00",
  "targets": [
    {
      "ip": "192.168.1.1",
      "is_up": true,
      "os_guess": "Linux/Unix (TTL=64)",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "version": "OpenSSH_8.2p1",
          "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu",
          "vuln_hints": [],
          "response_time_ms": 12.4
        }
      ]
    }
  ],
  "total_ports_scanned": 1004,
  "open_ports_found": 1
}

2. HTML Report

A polished, printable report with:

    Summary cards (hosts, ports, duration)

    Color-coded state badges

    Per-host tables

    CVE warning blocks

    Client-ready formatting

Open in any browser:
bash

firefox reports/scan.html

📋 Command-Line Reference
Target & Ports
Flag	Description
TARGETS	IP / CIDR / range / hostname / file
-p, --ports	80 | 22,80,443 | 1-1024 | top-100 | top-1000
Scan Types
Flag	Description
-sT, --connect	TCP Connect scan (default, no root)
-sS, --syn	TCP SYN stealth scan (root + Scapy)
-sU, --udp	UDP scan
Timing
Flag	Description
-T, --timing	paranoid / sneaky / polite / normal / aggressive / insane
--rate N	Custom packets per second
--timeout S	Per-probe timeout in seconds
--max-concurrent N	Concurrency limit (default 200)
Discovery
Flag	Description
-Pn, --no-discovery	Skip host discovery (assume up)
Output
Flag	Description
-oJ FILE	Write JSON report
-oH FILE	Write HTML report
--no-banner	Skip banner grabbing
Comparison
Flag	Description
--baseline FILE	Compare against previous JSON
Config
Flag	Description
-c, --config FILE	YAML config file
--log-level	DEBUG / INFO / WARNING / ERROR
Meta
Flag	Description
-h, --help	Show help
-V, --version	Show version
🌍 Real-World Workflows
Workflow 1 — Internal Network Discovery
bash

# Find live hosts on a subnet
portscanner 10.0.0.0/24 -Pn -p 22,80,443,445,3389

# Drill into a live host
portscanner 10.0.0.5 -p 1-65535 -T aggressive -oH report.html

Workflow 2 — Bug Bounty Recon
bash

# Scan a scoped domain
portscanner scanme.nmap.org -p top-1000 -T polite \
    -oJ nmap_org.json -oH nmap_org.html

# Look for vulnerable services
grep -i "cve" reports/scan.json

Workflow 3 — Lab Practice
bash

# Kali → Metasploitable2
sudo $(which portscanner) 192.168.56.101 -sS -p top-1000 -T aggressive

# DVWA (localhost)
portscanner 127.0.0.1 -p 80,8080 -oH dvwa.html

Workflow 4 — Compliance Audit
bash

# TLS inventory
portscanner 10.0.0.0/24 -p 443,8443 -T polite -oJ tls_inventory.json

# Port exposure check
portscanner 10.0.0.0/24 -p 21,23,135,139,445,3389 -Pn

Workflow 5 — Continuous Monitoring
bash

# Nightly at 2 AM
0 2 * * * cd /opt/portscanner && \
  python3 -m portscanner 10.0.0.0/24 -Pn -p top-1000 \
  -oJ reports/$(date +\%F).json

# Weekly diff
portscanner --baseline reports/2026-09-26.json \
    -oJ reports/2026-10-03.json

🧪 Testing
Run Unit Tests
bash

pip install -e ".[dev]"
pytest -v

Test Coverage
Test File	Covers
test_models.py	PortResult, ScanResult serialization
test_utils.py	Port parsing, target parsing
Manual Lab Tests
bash

# Start services on Kali
sudo systemctl start ssh
sudo systemctl start apache2
python3 -m http.server 8000 &

# Verify scanner finds them
portscanner 127.0.0.1 -p 22,80,8000

⚡ Performance Tuning
Benchmarks
Scenario	Concurrency	Duration
1 host × 1,004 ports	200	~0.9s
1 host × 65,535 ports	200	~100s
/24 network × 22 ports	200	~45s
/24 network × 1,000 ports	200	~15 min
Tuning Tips
Goal	Setting
Faster internal scans	-T aggressive --max-concurrent 500
Stealthy external scans	-T sneaky --rate 20
Avoid overwhelming targets	-T polite --rate 100
Cross-continental	--timeout 3.0
Memory Notes

Each pending probe costs ~2 KB. For 65,535 ports × 254 hosts (16 million probes):

    Unbounded → ~32 GB RAM (dangerous)

    --max-concurrent 200 → ~400 KB resident (safe)

Always keep concurrency bounded.
🔧 Troubleshooting
Symptom	Cause	Fix
portscanner: command not found	venv not activated	source .venv/bin/activate
sudo: portscanner: command not found	sudo doesn't inherit venv	Use sudo $(which portscanner)
SYN scan requires root	Non-privileged user	Prefix with sudo
0 open ports everywhere	No services running	Start SSH/HTTP on target
Scapy not installed	Missing dependency	pip install scapy
Very slow scans	Low rate / high timeout	Use -T aggressive
Cannot resolve hostname	DNS failure	Check /etc/resolv.conf
Connection refused on all ports	Windows firewall blocks	Expected on Windows targets
HTML report empty	No findings	Scan a live host with services
Unicode issues in terminal	Locale misconfigured	export LC_ALL=C.UTF-8
Debug Mode
bash

portscanner 127.0.0.1 -p top-100 --log-level DEBUG

Verify Installation
bash

python3 -c "import portscanner; print(portscanner.__version__)"

📁 Project Structure
text

portscanner/
├── config/
│   └── default.yaml                # Baseline scan config
├── examples/
│   ├── sample_config.yaml          # Example profile
│   └── sample_targets.txt          # Example target file
├── src/
│   └── portscanner/
│       ├── __init__.py             # Version
│       ├── __main__.py             # python -m entry
│       ├── banner.py               # Banner grabbing
│       ├── cli.py                  # Click CLI
│       ├── compare.py              # Baseline diff
│       ├── config.py               # YAML loader
│       ├── discovery.py            # Host discovery
│       ├── engine.py               # Async orchestration
│       ├── models.py               # Data models
│       ├── rate_limit.py           # Token bucket
│       ├── utils.py                # Parsing helpers
│       ├── vulnhints.py            # CVE hint DB
│       ├── reporters/
│       │   ├── __init__.py
│       │   ├── html_reporter.py
│       │   └── json_reporter.py
│       └── scanner/
│           ├── __init__.py
│           ├── base.py             # Scanner ABC
│           ├── connect.py          # TCP Connect
│           ├── syn.py              # TCP SYN
│           └── udp.py              # UDP
├── templates/
│   └── report.html.j2              # Jinja2 template
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   └── test_utils.py
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
└── requirements.txt

🧩 Design Decisions
Why asyncio over threads?

Network I/O is fundamentally I/O-bound. While one coroutine waits for a SYN-ACK, others proceed. asyncio.Semaphore costs ~100 bytes; thread lock + stack costs ~8 KB. At 10,000 concurrent probes, that's 100 MB vs 80 GB.
Why a local CVE database?

Air-gap compatibility, deterministic speed, and full control over false-positive rate. Consulting NVD at scan-time adds latency, requires internet, and is rate-limited.
Why Click over argparse?

Better help text, nested commands, and future extension to subcommands (portscanner scan, portscanner compare). Click is the modern standard for Python CLIs.
Why Rich for terminal output?

Color-coded tables, live progress bars with ETA, and rich panel boxes are essential for a tool that may run for hours. Rich handles Windows/ANSI portability automatically.
Why Jinja2 for HTML?

Separation of report data and presentation. The template can be edited without touching Python code — useful for customization and white-labeling.
Why Scapy for SYN scan?

Only way to craft raw IP/TCP packets in pure Python. Alternatives (raw sockets, ctypes) are platform-specific and far more code.
🎓 Interview Preparation
Likely Questions & Answers

Q: Walk me through your port scanner.

    "It's a three-stage async pipeline: discovery → scan → report. Discovery finds live hosts via ICMP and TCP pings. Scanning uses asyncio with a semaphore and token-bucket rate limiter, running one of three engines — TCP connect, raw SYN via Scapy, or UDP. Open ports get banner-grabbed and matched against a local CVE hint database. Reports are emitted as JSON and Jinja2-rendered HTML. The CLI is built on Click with Rich for the terminal UI."

Q: Why asyncio instead of threads?

    "Network I/O is I/O-bound — the CPU is idle 99% of the time while waiting for responses. asyncio uses a single thread and event loop, so thousands of pending probes cost kilobytes instead of megabytes. At scale, threads also hit Python's GIL and OS thread limits. asyncio scales cleanly to 10,000+ concurrent operations on a laptop."

Q: How does your rate limiter work?

    "Token bucket algorithm. Each probe calls acquire(), which refills tokens based on elapsed time. If a token is available, consume it and proceed; otherwise sleep until the next refill. A single asyncio.Lock ensures fairness. This gives precise control over packets-per-second, matching Nmap's timing templates — paranoid at 5 pps, insane at 5000 pps."

Q: Why does SYN scan need root?

    "SYN scanning uses raw sockets to craft IP packets manually. On Linux, creating a raw socket requires CAP_NET_RAW — a root-only capability. TCP Connect scanning uses the standard socket API, which any user can call. That's why Connect is the default and SYN is opt-in with sudo."

Q: How do you avoid false positives in banner grabbing?

    "Two techniques: passive read first, active probe only when needed. HTTP servers stay silent until asked, so we send a HEAD / request. Many SSH/FTP/SMTP servers send banners immediately, so we just read. A confidence field on each result distinguishes confirmed (parsed from banner) from guess (port-only mapping) from none."

Q: How would you scale this to 1 million IPs?

    "Three changes. First, add a distributed worker mode — a coordinator distributes /16 chunks to worker nodes over gRPC. Second, persist results to SQLite as they stream so a crash doesn't lose hours of work. Third, tune the semaphore per-worker to avoid overwhelming the source NIC. The core asyncio engine is already O(1) memory per pending probe."

Q: What's the biggest weakness of your tool?

    "It's single-node. A 65,535-port × /16 scan takes hours on one machine. Distributed execution would help. Also, the CVE hint database is curated, not exhaustive — Nuclei integration would extend coverage. And SYN scanning uses a thread pool under the hood because Scapy isn't fully thread-safe, which caps SYN throughput."

⚠️ Ethical & Legal Notice
<div align="center">
🛑 READ THIS BEFORE USING
</div>

This tool is for authorized security testing only.

By using this tool you acknowledge that:

    You own the target systems, OR

    You have explicit written permission to test them

Legal Frameworks
Jurisdiction	Law	Penalty
🇺🇸 USA	Computer Fraud and Abuse Act (CFAA)	Up to 10 years imprisonment
🇬🇧 UK	Computer Misuse Act 1990	Up to 10 years imprisonment
🇮🇳 India	IT Act § 43, § 66	Civil + criminal penalties
🇪🇺 EU	Cybercrime Convention	Varies by member state
Safe Practice Targets

    ✅ 127.0.0.1 — your own machine

    ✅ 192.168.x.x — your own LAN

    ✅ scanme.nmap.org — Nmap's authorized public target

    ✅ Metasploitable2 — intentionally vulnerable VM

    ✅ DVWA — Damn Vulnerable Web Application

    ✅ HackTheBox / TryHackMe — subscriber labs

    ✅ HackerOne / Bugcrowd — scoped programs

Do Not

    ❌ Scan IPs you don't own

    ❌ Scan public IPs without written authorization

    ❌ Use aggressive timing on shared infrastructure

    ❌ Publish scan results containing third-party data

The author assumes no liability for misuse. Use responsibly.
🗺️ Roadmap
v1.1 — Depth

    □

    SSL/TLS certificate audit
    □

    HTTP security header check
    □

    DNS zone transfer testing
    □

    Subdomain enumeration

v1.2 — Scale

    □

    Distributed worker mode (gRPC)
    □

    SQLite result streaming
    □

    Resume from checkpoint
    □

    Adaptive rate limiting

v1.3 — Integration

    □

    Nuclei template runner
    □

    Nmap XML import for comparison
    □

    Slack / webhook notifications
    □

    Prometheus metrics export

v2.0 — Platform

    □

    Web dashboard (FastAPI + React)
    □

    REST API for automation
    □

    Plugin system for custom scanners
    □

    PyPI distribution

🤝 Contributing
How to Contribute

    Fork the repository

    Create a feature branch: git checkout -b feature/my-feature

    Commit your changes: git commit -m "feat: add my feature"

    Push to the branch: git push origin feature/my-feature

    Open a Pull Request

Development Setup
bash

git clone https://github.com/xss-pushpensh/portscanner.git
cd portscanner
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest -v

# Format code
black src/
ruff check src/

Code Style

    PEP 8 compliant

    Type hints on all public functions

    Docstrings on every module

    Tests for new functionality

    No new dependencies unless truly needed

Commit Convention
text

feat: add SSL/TLS audit module
fix: rate limiter edge case on empty queue
docs: update README with new examples
test: add banner parsing unit tests
refactor: extract rate limiter into its own module

📜 License
text

MIT License

Copyright (c) 2026 XSS.PUSHPENSH

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

👤 Author

XSS.PUSHPENSH

    🐙 GitHub: @xss-pushpensh

    💼 LinkedIn: in/xss-pushpensh

    📧 Email: xss.pushpensh@gmail.com

Building security tools one module at a time.
