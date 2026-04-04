# ⚡ VulnHawk — Network Vulnerability Assessment Framework

```
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝
```

**VulnHawk** is a modular, extensible CLI framework for network vulnerability assessment — built for Network Admins and IT Security Teams. It goes beyond basic port scanning to give you actionable intelligence about your attack surface.

> ⚠️ **LEGAL NOTICE**: VulnHawk is for authorized security testing ONLY. Only scan systems you own or have explicit written permission to assess. Unauthorized scanning is illegal.

---

## 🎯 What VulnHawk Does

| Module | What It Checks |
|--------|----------------|
| **Port Scanner** | Multi-threaded TCP scan (common / top-1000 / full / custom) |
| **Service Detection** | Banner grabbing, service version identification |
| **CVE Checker** | Matches versions against known CVE database (SSH, Apache, nginx, MySQL, Redis, etc.) |
| **Dangerous Ports** | Flags inherently risky open ports (Telnet, RDP, Redis, SMB, MongoDB, etc.) |
| **SSL/TLS Analyzer** | Protocol version, cipher suite, certificate expiry, self-signed, weak ciphers |
| **HTTP Auditor** | Missing security headers (HSTS, CSP, X-Frame-Options), info disclosure, TRACE method |
| **DNS Recon** | Zone transfer, SPF/DMARC, DNSSEC, subdomain enumeration, wildcard DNS |
| **Report Generator** | Professional HTML + JSON reports with remediation roadmap |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd vulnhawk
pip install -r requirements.txt
```

### 2. Run Your First Scan

```bash
# Scan common ports (fastest)
python vulnhawk.py -t 192.168.1.1

# Scan with verbose output
python vulnhawk.py -t example.com -v

# Full scan — all ports, all modules
python vulnhawk.py -t example.com --full --dns -v
```

---

## 📖 Usage

```
usage: vulnhawk [-h] -t TARGET [--common | --top1000 | --full | --ports PORTS | --range RANGE]
                [--ssl] [--no-ssl] [--http] [--no-http] [--dns] [--no-vuln]
                [--timeout TIMEOUT] [--threads THREADS]
                [--format {json,html,both,none}] [--output-dir OUTPUT_DIR]
                [-v] [--no-banner]
```

### Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target hostname or IP (required) | — |
| `--common` | Scan ~50 most common ports | ✓ default |
| `--top1000` | Scan top 1000 ports | — |
| `--full` | Full port scan 1-65535 | — |
| `--ports 22,80,443` | Custom port list | — |
| `--range 1-1024` | Port range | — |
| `--ssl / --no-ssl` | SSL/TLS analysis | on |
| `--http / --no-http` | HTTP security audit | on |
| `--dns` | DNS reconnaissance | off |
| `--no-vuln` | Skip CVE checks | off |
| `--timeout` | TCP connect timeout (secs) | 1.0 |
| `--threads` | Concurrent scan threads | 150 |
| `--format` | Report format: json/html/both/none | both |
| `--output-dir` | Report save directory | ./reports |
| `-v, --verbose` | Verbose output | off |

---

## 💡 Examples

```bash
# Quick recon — just port scan, no reports
python vulnhawk.py -t 10.0.0.1 --format none

# Check a web server comprehensively
python vulnhawk.py -t myserver.com --ports 80,443,8080,8443 --ssl --http -v

# Internal network server audit
python vulnhawk.py -t 192.168.1.50 --top1000 --dns --format html

# Slow & thorough — full scan, 2s timeout
python vulnhawk.py -t 10.0.0.1 --full --timeout 2.0 --threads 100

# Fast recon — no SSL or HTTP checks, high threads
python vulnhawk.py -t 10.0.0.1 --no-ssl --no-http --threads 300

# Check only specific high-risk ports
python vulnhawk.py -t 192.168.1.1 --ports 21,22,23,445,3306,3389,6379,27017
```

---

## 📁 Project Structure

```
vulnhawk/
├── vulnhawk.py              ← Main CLI entry point
├── requirements.txt
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── engine.py            ← Scan orchestration engine
│   ├── port_scanner.py      ← Multi-threaded TCP scanner
│   ├── ssl_analyzer.py      ← SSL/TLS certificate & config checks
│   ├── vuln_checker.py      ← CVE & dangerous port detection
│   └── reporter.py          ← HTML + JSON report generator
│
├── plugins/
│   ├── __init__.py
│   ├── http_audit.py        ← HTTP security headers & methods
│   └── dns_recon.py         ← DNS recon, SPF/DMARC, zone transfer
│
├── data/
│   └── vuln_signatures.json ← CVE database & vulnerability signatures
│
└── reports/                 ← Generated reports saved here
```

---

## 🔍 What Gets Detected

### CVE Coverage (sample)
| Service | CVEs in Database |
|---------|-----------------|
| OpenSSH | CVE-2016-6515, CVE-2015-5600, CVE-2016-0777 |
| Apache | CVE-2021-41773 (Path Traversal/RCE), CVE-2021-42013 |
| nginx | CVE-2021-23017, CVE-2019-9511 |
| vsftpd | CVE-2011-2523 (Backdoor!) |
| MySQL | CVE-2012-2122 (Auth bypass) |
| Redis | CVE-2019-10192, CVE-2020-14147 |
| Samba | CVE-2017-7494 (SambaCry RCE) |
| Tomcat | CVE-2020-1938 (Ghostcat) |

### Dangerous Port Flags
Telnet (23), FTP (21), SMB (445), RDP (3389), Redis (6379), MongoDB (27017), Elasticsearch (9200), TFTP (69), rsh/rlogin (512-514), and 20+ more.

### SSL/TLS Issues
- Expired / expiring certificates
- Self-signed certificates  
- SSLv2, SSLv3, TLS 1.0, TLS 1.1 support
- Weak cipher suites (RC4, DES, 3DES, MD5, NULL)
- Short-lived HSTS max-age

### HTTP Security Headers
Missing: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy  
Dangerous methods: TRACE, TRACK, PUT, DELETE  
Info disclosure: Server version, X-Powered-By  
Cookie security: Missing Secure, HttpOnly, SameSite flags

### DNS Security
- Zone transfer (AXFR) vulnerability
- Missing or weak SPF record
- Missing or permissive DMARC policy
- DNSSEC not enabled
- Wildcard DNS misconfiguration
- Subdomain enumeration (30+ common subdomains)

---

## 📊 Risk Scoring

VulnHawk calculates a cumulative risk score:

| Severity | Points |
|----------|--------|
| CRITICAL | +10 |
| HIGH | +7 |
| MEDIUM | +4 |
| LOW | +2 |

| Score | Risk Level |
|-------|------------|
| 50+ | CRITICAL |
| 30–49 | HIGH |
| 15–29 | MEDIUM |
| 5–14 | LOW |
| 0–4 | MINIMAL |

---

## 🔌 Extending VulnHawk

Add a new plugin in `plugins/`:

```python
# plugins/my_check.py
from dataclasses import dataclass, field
from typing import List

@dataclass
class MyFinding:
    severity: str
    title: str
    description: str

@dataclass
class MyCheckResult:
    host: str
    findings: List[MyFinding] = field(default_factory=list)

class MyChecker:
    def check(self, host: str, port: int) -> MyCheckResult:
        result = MyCheckResult(host=host)
        # ... your logic here
        return result
```

Then call it in `core/engine.py` in the `run()` method.

Add CVE signatures to `data/vuln_signatures.json`:
```json
{
  "service_cves": {
    "MyService": [
      {
        "version_range": ["1.0", "2.5"],
        "cve": "CVE-2024-XXXX",
        "severity": "HIGH",
        "desc": "Description of the vulnerability"
      }
    ]
  }
}
```

---

## 📋 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no critical findings |
| 1 | Critical vulnerabilities found OR scan error |

This makes VulnHawk CI/CD friendly — pipe it into your security pipeline.

---

## 🛠 Requirements

- Python 3.8+
- `rich` >= 13.0.0 (for terminal UI)
- `packaging` >= 23.0 (for version comparison)
- `dig` / `nslookup` (for DNS recon, usually pre-installed on Linux/macOS)
- Network access to target (firewall rules permitting)

---

## ⚖️ Legal & Ethical Use

VulnHawk is a security assessment tool for authorized use only:

- ✅ Scanning your own infrastructure
- ✅ Scanning with written permission from the system owner
- ✅ Bug bounty programs (within defined scope)
- ✅ Penetration testing engagements with signed authorization
- ❌ Scanning systems without permission — **illegal in most jurisdictions**

The authors accept no liability for misuse of this tool.

---

*VulnHawk v1.0 — Built for Network Admins & IT Security Teams*
# VulnHawk
