"""
VulnHawk Scan Engine
Orchestrates port scanning, vulnerability checking, SSL/HTTP/DNS analysis.
"""

import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable

from .port_scanner import PortScanner, ScanResult
from .ssl_analyzer import SSLAnalyzer
from .vuln_checker import VulnerabilityChecker


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    target: str
    scan_type: str = "common"       # common | top1000 | full | custom
    ports: Optional[List[int]] = None
    port_range: Optional[tuple] = None
    timeout: float = 1.0
    threads: int = 150
    check_ssl: bool = True
    check_http: bool = True
    check_dns: bool = False
    check_vulns: bool = True
    output_format: str = "both"     # json | html | both | none
    output_dir: str = "reports"
    verbose: bool = False


class ScanEngine:
    """
    Central scan orchestration engine.
    Runs all scan modules and aggregates results.
    """

    def __init__(self, config: ScanConfig, progress_cb: Optional[Callable] = None):
        self.config = config
        self.progress_cb = progress_cb
        self.port_scanner = PortScanner(
            timeout=config.timeout,
            max_threads=config.threads
        )
        self.ssl_analyzer = SSLAnalyzer(timeout=5.0)
        self.vuln_checker = VulnerabilityChecker()

    def _update_progress(self, stage: str, detail: str = ""):
        if self.progress_cb:
            self.progress_cb(stage, detail)

    def run(self) -> Dict[str, Any]:
        """Execute full scan and return aggregated result dict."""
        config = self.config
        result = {
            "target": config.target,
            "ip": "",
            "hostname": "",
            "scan_date": datetime.datetime.utcnow().isoformat(),
            "scan_time": 0,
            "scan_type": config.scan_type,
            "open_ports": [],
            "vulnerabilities": [],
            "dangerous_ports": [],
            "ssl": {},
            "http": {},
            "dns": {},
            "remediation": [],
            "risk_score": 0,
            "summary": {}
        }

        # --- Phase 1: Port Scan ---
        self._update_progress("SCAN", f"Port scanning {config.target}...")

        # Set up port scanner progress callback
        port_results: List[Dict] = []
        scan_result: ScanResult = self.port_scanner.scan(
            target=config.target,
            ports=config.ports,
            port_range=config.port_range,
            scan_type=config.scan_type
        )

        result["ip"] = scan_result.ip
        result["hostname"] = scan_result.hostname
        result["scan_time"] = scan_result.scan_time
        result["errors"] = scan_result.errors

        # Convert open ports to serializable dicts
        for p in scan_result.open_ports:
            port_results.append({
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "banner": p.banner,
                "protocol": p.protocol,
                "latency_ms": p.latency_ms
            })
        result["open_ports"] = port_results

        if not scan_result.ip and scan_result.errors:
            result["errors"] = scan_result.errors
            return result

        # --- Phase 2: Vulnerability Check ---
        if config.check_vulns and port_results:
            self._update_progress("VULN", "Checking for known vulnerabilities...")
            vuln_result = self.vuln_checker.check_all(config.target, port_results)

            result["vulnerabilities"] = [
                {
                    "cve": v.cve,
                    "service": v.service,
                    "detected_version": v.detected_version,
                    "severity": v.severity,
                    "description": v.description,
                    "port": v.port,
                    "remediation": v.remediation
                }
                for v in vuln_result.vulnerabilities
            ]

            result["dangerous_ports"] = [
                {
                    "port": dp.port,
                    "service": dp.service,
                    "risk": dp.risk,
                    "reason": dp.reason
                }
                for dp in vuln_result.dangerous_ports
            ]

            # Remediation roadmap
            result["remediation"] = self.vuln_checker.get_remediation_priority(vuln_result)

        # --- Phase 3: SSL Analysis ---
        if config.check_ssl:
            ssl_ports = [p for p in scan_result.open_port_numbers if p in (443, 8443, 465, 993, 995, 636)]
            if not ssl_ports:
                # Try 443 anyway if HTTP is open
                if 80 in scan_result.open_port_numbers or 8080 in scan_result.open_port_numbers:
                    ssl_ports = [443]

            for ssl_port in ssl_ports[:2]:  # Check first 2 SSL ports
                self._update_progress("SSL", f"Analyzing SSL/TLS on port {ssl_port}...")
                ssl_res = self.ssl_analyzer.analyze(config.target, ssl_port)

                if ssl_res.supported or ssl_res.findings:
                    cert_data = {}
                    if ssl_res.certificate:
                        cert = ssl_res.certificate
                        cert_data = {
                            "subject": cert.subject,
                            "issuer": cert.issuer,
                            "not_before": str(cert.not_before),
                            "not_after": str(cert.not_after),
                            "days_until_expiry": cert.days_until_expiry,
                            "is_expired": cert.is_expired,
                            "is_self_signed": cert.is_self_signed,
                            "san": cert.san,
                            "wildcard": cert.wildcard
                        }

                    result["ssl"] = {
                        "host": ssl_res.host,
                        "port": ssl_res.port,
                        "supported": ssl_res.supported,
                        "protocol_version": ssl_res.protocol_version,
                        "cipher_suite": ssl_res.cipher_suite,
                        "certificate": cert_data,
                        "findings": [
                            {
                                "severity": f.severity,
                                "title": f.title,
                                "description": f.description,
                                "recommendation": f.recommendation
                            }
                            for f in ssl_res.findings
                        ],
                        "risk_score": ssl_res.risk_score
                    }
                    # Add SSL vulns to remediation
                    for f in ssl_res.findings:
                        if f.severity in ("CRITICAL", "HIGH"):
                            result["remediation"].append({
                                "priority": len(result["remediation"]) + 1,
                                "type": "SSL/TLS",
                                "severity": f.severity,
                                "title": f.title,
                                "action": f.recommendation,
                                "reference": ""
                            })
                break  # Only analyze first found SSL port

        # --- Phase 4: HTTP Audit ---
        if config.check_http:
            http_ports = [p for p in scan_result.open_port_numbers
                          if p in (80, 443, 8080, 8443, 8888, 3000, 5000)]
            if http_ports:
                http_port = http_ports[0]
                use_ssl = http_port in (443, 8443)
                self._update_progress("HTTP", f"Auditing HTTP security on port {http_port}...")

                try:
                    from ..plugins.http_audit import HTTPAuditor
                    auditor = HTTPAuditor()
                    http_res = auditor.audit(config.target, http_port, use_ssl)

                    result["http"] = {
                        "url": http_res.url,
                        "status_code": http_res.status_code,
                        "server_header": http_res.server_header,
                        "powered_by": http_res.powered_by,
                        "redirects_to_https": http_res.redirects_to_https,
                        "methods_allowed": http_res.methods_allowed,
                        "findings": [
                            {
                                "severity": f.severity,
                                "title": f.title,
                                "description": f.description,
                                "evidence": f.evidence,
                                "recommendation": f.recommendation
                            }
                            for f in http_res.findings
                        ]
                    }
                    for f in http_res.findings:
                        if f.severity in ("CRITICAL", "HIGH"):
                            result["remediation"].append({
                                "priority": len(result["remediation"]) + 1,
                                "type": "HTTP",
                                "severity": f.severity,
                                "title": f.title,
                                "action": f.recommendation,
                                "reference": ""
                            })
                except ImportError:
                    pass

        # --- Phase 5: DNS Recon ---
        if config.check_dns:
            self._update_progress("DNS", f"Performing DNS reconnaissance on {config.target}...")
            try:
                from ..plugins.dns_recon import DNSRecon
                dns = DNSRecon()
                # Extract domain from target (remove subdomain if IP)
                import re
                domain = config.target
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", config.target):
                    domain = config.target  # It's an IP, skip DNS
                else:
                    dns_res = dns.recon(domain)
                    result["dns"] = {
                        "domain": dns_res.domain,
                        "nameservers": dns_res.nameservers,
                        "mx_records": dns_res.mx_records,
                        "spf_record": dns_res.spf_record,
                        "dmarc_record": dns_res.dmarc_record,
                        "dnssec_enabled": dns_res.dnssec_enabled,
                        "zone_transfer_vulnerable": dns_res.zone_transfer_vulnerable,
                        "subdomains": dns_res.subdomains,
                        "records": [
                            {"type": r.record_type, "name": r.name, "value": r.value}
                            for r in dns_res.records
                        ],
                        "findings": [
                            {
                                "severity": f.severity,
                                "title": f.title,
                                "description": f.description,
                                "evidence": f.evidence,
                                "recommendation": f.recommendation
                            }
                            for f in dns_res.findings
                        ]
                    }
                    for f in dns_res.findings:
                        if f.severity in ("CRITICAL", "HIGH"):
                            result["remediation"].append({
                                "priority": len(result["remediation"]) + 1,
                                "type": "DNS",
                                "severity": f.severity,
                                "title": f.title,
                                "action": f.recommendation,
                                "reference": ""
                            })
            except ImportError:
                pass

        # --- Compute Risk Score ---
        sev_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
        risk = sum(sev_weights.get(v["severity"], 0) for v in result["vulnerabilities"])
        risk += sum(sev_weights.get(dp["risk"], 0) for dp in result["dangerous_ports"])
        for f in result.get("ssl", {}).get("findings", []):
            risk += sev_weights.get(f["severity"], 0)
        result["risk_score"] = risk

        # Sort remediation by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        result["remediation"] = sorted(
            result["remediation"],
            key=lambda x: sev_order.get(x.get("severity", "INFO"), 5)
        )
        for i, item in enumerate(result["remediation"]):
            item["priority"] = i + 1

        # --- Summary ---
        result["summary"] = {
            "total_open_ports": len(result["open_ports"]),
            "critical_vulns": sum(1 for v in result["vulnerabilities"] if v["severity"] == "CRITICAL"),
            "high_vulns": sum(1 for v in result["vulnerabilities"] if v["severity"] == "HIGH"),
            "medium_vulns": sum(1 for v in result["vulnerabilities"] if v["severity"] == "MEDIUM"),
            "low_vulns": sum(1 for v in result["vulnerabilities"] if v["severity"] == "LOW"),
            "dangerous_ports": len(result["dangerous_ports"]),
            "ssl_issues": len(result.get("ssl", {}).get("findings", [])),
            "http_issues": len(result.get("http", {}).get("findings", [])),
            "risk_score": result["risk_score"],
            "risk_level": self._risk_level(result["risk_score"])
        }

        return result

    def _risk_level(self, score: int) -> str:
        if score >= 50:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        elif score >= 5:
            return "LOW"
        return "MINIMAL"
