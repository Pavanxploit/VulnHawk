"""
VulnHawk Vulnerability Checker
Checks for known vulnerabilities based on service banners and versions.
"""

import re
import json
import os
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from packaging import version as pkg_version


@dataclass
class Vulnerability:
    cve: str
    service: str
    detected_version: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    port: int = 0
    cvss_score: float = 0.0
    remediation: str = ""

    @property
    def severity_color(self) -> str:
        colors = {
            "CRITICAL": "red",
            "HIGH": "bright_red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue"
        }
        return colors.get(self.severity, "white")


@dataclass
class DangerousPort:
    port: int
    service: str
    risk: str
    reason: str


@dataclass
class VulnCheckResult:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    dangerous_ports: List[DangerousPort] = field(default_factory=list)
    weak_credentials: List[Dict] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "HIGH")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "MEDIUM")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == "LOW")

    @property
    def risk_score(self) -> int:
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2}
        return sum(weights.get(v.severity, 0) for v in self.vulnerabilities)


# Version extraction patterns
VERSION_PATTERNS = [
    r"(\d+\.\d+\.\d+[-\w]*)",   # x.y.z
    r"(\d+\.\d+[-\w]*)",         # x.y
    r"v(\d+\.\d+\.\d+)",         # vX.Y.Z
]

# Service name normalization
SERVICE_ALIASES = {
    "openssh": "OpenSSH",
    "ssh": "OpenSSH",
    "apache": "Apache",
    "apache httpd": "Apache",
    "apache/": "Apache",
    "nginx": "nginx",
    "vsftpd": "vsftpd",
    "proftpd": "ProFTPD",
    "mysql": "MySQL",
    "mariadb": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "samba": "Samba",
    "smbd": "Samba",
    "redis": "Redis",
    "tomcat": "Tomcat",
    "apache tomcat": "Tomcat",
}


def _load_signatures() -> Dict:
    """Load vulnerability signatures from the data file."""
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "vuln_signatures.json"
    )
    try:
        with open(data_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"service_cves": {}, "dangerous_ports": {}}


def extract_version(banner: str) -> Optional[str]:
    """Extract version string from a banner."""
    for pattern in VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1).lstrip("v")
    return None


def identify_service(banner: str, port: int = 0) -> Optional[str]:
    """Identify service name from banner."""
    banner_lower = banner.lower()
    for alias, canonical in SERVICE_ALIASES.items():
        if alias in banner_lower:
            return canonical
    return None


def compare_versions(version_str: str, range_min: str, range_max: str) -> bool:
    """Check if version falls within [min, max] range."""
    try:
        ver = pkg_version.parse(version_str)
        vmin = pkg_version.parse(range_min)
        vmax = pkg_version.parse(range_max)
        return vmin <= ver <= vmax
    except Exception:
        # Fallback to string comparison
        return range_min <= version_str <= range_max


class VulnerabilityChecker:
    """Check for known vulnerabilities on discovered services."""

    def __init__(self):
        self.signatures = _load_signatures()

    def check_all(
        self,
        target: str,
        open_ports: List[Dict],   # [{port, service, banner}, ...]
    ) -> VulnCheckResult:
        """
        Run all vulnerability checks.

        Args:
            target: Target hostname/IP
            open_ports: List of open port dicts with port, service, banner
        """
        result = VulnCheckResult(target=target)

        for port_info in open_ports:
            port = port_info.get("port", 0)
            service = port_info.get("service", "")
            banner = port_info.get("banner", "")

            # 1. Check for dangerous ports
            dangerous = self._check_dangerous_port(port)
            if dangerous:
                result.dangerous_ports.append(dangerous)

            # 2. Check CVEs from banner
            cves = self._check_cves(port, service, banner)
            result.vulnerabilities.extend(cves)

        return result

    def _check_dangerous_port(self, port: int) -> Optional[DangerousPort]:
        """Check if port is inherently dangerous."""
        dangerous_db = self.signatures.get("dangerous_ports", {})
        port_info = dangerous_db.get(str(port))
        if port_info:
            return DangerousPort(
                port=port,
                service=port_info["service"],
                risk=port_info["risk"],
                reason=port_info["reason"]
            )
        return None

    def _check_cves(self, port: int, service: str, banner: str) -> List[Vulnerability]:
        """Match banner/service against CVE database."""
        vulns = []

        if not banner and not service:
            return vulns

        combined = f"{service} {banner}".strip()

        # Identify canonical service name
        canonical_service = identify_service(combined, port)
        if not canonical_service:
            canonical_service = identify_service(service, port)

        if not canonical_service:
            return vulns

        # Extract version
        detected_version = extract_version(banner) or extract_version(service)

        if not detected_version:
            # Can still flag known-dangerous old patterns
            return vulns

        # Lookup CVEs
        cve_db = self.signatures.get("service_cves", {})
        service_cves = cve_db.get(canonical_service, [])

        for cve_entry in service_cves:
            vmin = cve_entry.get("version_range", ["0", "9999"])[0]
            vmax = cve_entry.get("version_range", ["0", "9999"])[1]

            if compare_versions(detected_version, vmin, vmax):
                vulns.append(Vulnerability(
                    cve=cve_entry["cve"],
                    service=canonical_service,
                    detected_version=detected_version,
                    severity=cve_entry["severity"],
                    description=cve_entry["desc"],
                    port=port,
                    remediation=f"Upgrade {canonical_service} to the latest stable version."
                ))

        return vulns

    def check_default_credentials(self, host: str, open_ports: List[Dict]) -> List[Dict]:
        """
        Check for default/weak credentials on common services.
        Returns list of findings.
        """
        findings = []
        weak_creds_db = self.signatures.get("weak_credentials", {})

        service_port_map = {
            21: "ftp",
            22: "ssh",
            3306: "mysql",
            6379: "redis",
        }

        for port_info in open_ports:
            port = port_info.get("port", 0)
            service_key = service_port_map.get(port)

            if service_key and service_key in weak_creds_db:
                creds = weak_creds_db[service_key]
                findings.append({
                    "port": port,
                    "service": service_key.upper(),
                    "credentials_to_test": creds,
                    "note": f"Default credentials exist for {service_key.upper()} — manual verification recommended."
                })

        return findings

    def get_remediation_priority(self, result: VulnCheckResult) -> List[Dict]:
        """Return a prioritized remediation list."""
        priorities = []

        # Critical vulnerabilities first
        for v in sorted(result.vulnerabilities, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.severity, 4)
        )):
            priorities.append({
                "priority": len(priorities) + 1,
                "type": "CVE",
                "severity": v.severity,
                "title": f"{v.cve} on port {v.port} ({v.service} {v.detected_version})",
                "action": v.remediation or f"Update {v.service} to latest version",
                "reference": f"https://nvd.nist.gov/vuln/detail/{v.cve}"
            })

        # Dangerous ports
        for dp in sorted(result.dangerous_ports, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.risk, 4)
        )):
            priorities.append({
                "priority": len(priorities) + 1,
                "type": "EXPOSURE",
                "severity": dp.risk,
                "title": f"Exposed {dp.service} on port {dp.port}",
                "action": f"Firewall port {dp.port} from public access. {dp.reason}",
                "reference": ""
            })

        return priorities
