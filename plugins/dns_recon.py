"""
VulnHawk DNS Reconnaissance Plugin
Performs DNS enumeration, zone transfer attempts, and DNS security checks.
"""

import socket
import subprocess
import re
import platform
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DNSRecord:
    record_type: str    # A, AAAA, MX, NS, TXT, CNAME, SOA, PTR
    name: str
    value: str
    ttl: int = 0


@dataclass
class DNSFinding:
    severity: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class DNSReconResult:
    domain: str
    records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    findings: List[DNSFinding] = field(default_factory=list)
    zone_transfer_vulnerable: bool = False
    nameservers: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dnssec_enabled: bool = False


# Common subdomains to enumerate
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "internal", "intranet", "extranet",
    "smtp", "pop", "imap", "webmail", "owa", "exchange", "autodiscover",
    "m", "mobile", "app", "apps", "web", "secure", "login", "auth",
    "sso", "identity", "accounts", "panel", "dashboard", "manage",
    "management", "monitoring", "nagios", "zabbix", "grafana",
    "jenkins", "jira", "confluence", "wiki", "gitlab", "github",
    "git", "svn", "repo", "cdn", "static", "media", "assets",
    "img", "images", "files", "downloads", "upload", "uploads",
    "mysql", "db", "database", "redis", "mongo", "elasticsearch",
    "backup", "backups", "old", "new", "beta", "alpha", "demo",
    "sandbox", "lab", "labs", "research", "docs", "documentation",
    "blog", "news", "shop", "store", "helpdesk", "support", "ticket",
    "remote1", "remote2", "vpn1", "vpn2", "fw", "firewall",
    "proxy", "mx1", "mx2", "ns1", "ns2", "dns1", "dns2",
]


def _resolve(hostname: str, record_type: str = "A") -> List[str]:
    """Simple DNS resolution using socket."""
    results = []
    try:
        if record_type == "A":
            info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            results = list(set([i[4][0] for i in info]))
        elif record_type == "AAAA":
            info = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            results = list(set([i[4][0] for i in info]))
    except (socket.gaierror, OSError):
        pass
    return results


def _nslookup(domain: str, record_type: str, nameserver: str = "") -> List[str]:
    """Run nslookup/dig for various record types."""
    results = []
    system = platform.system().lower()

    try:
        if system in ("linux", "darwin"):
            cmd = ["dig", "+short", record_type, domain]
            if nameserver:
                cmd.extend([f"@{nameserver}"])
        else:
            cmd = ["nslookup", f"-type={record_type}", domain]
            if nameserver:
                cmd.append(nameserver)

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = proc.stdout.strip()

        if output:
            results = [line.strip().rstrip(".") for line in output.splitlines() if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return results


def _attempt_zone_transfer(domain: str, nameserver: str) -> List[str]:
    """Attempt DNS zone transfer (AXFR)."""
    records = []
    try:
        cmd = ["dig", f"@{nameserver}", domain, "AXFR", "+noall", "+answer"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout.strip()

        if output and "Transfer failed" not in output and "REFUSED" not in output:
            for line in output.splitlines():
                if line.strip() and not line.startswith(";"):
                    records.append(line.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return records


class DNSRecon:
    """DNS reconnaissance and security checks."""

    def __init__(self, timeout: float = 3.0, threads: int = 50):
        self.timeout = timeout
        self.threads = threads

    def recon(self, domain: str, deep: bool = False) -> DNSReconResult:
        """
        Perform DNS reconnaissance on a domain.

        Args:
            domain: Target domain (e.g. example.com)
            deep: If True, run subdomain enumeration
        """
        result = DNSReconResult(domain=domain)

        # 1. Resolve A records
        a_records = _resolve(domain, "A")
        for ip in a_records:
            result.records.append(DNSRecord("A", domain, ip))

        # 2. Nameservers
        ns_records = _nslookup(domain, "NS")
        result.nameservers = ns_records
        for ns in ns_records:
            result.records.append(DNSRecord("NS", domain, ns))

        # 3. MX records
        mx_records = _nslookup(domain, "MX")
        result.mx_records = mx_records
        for mx in mx_records:
            result.records.append(DNSRecord("MX", domain, mx))

        # 4. TXT records (SPF, DMARC, etc.)
        txt_records = _nslookup(domain, "TXT")
        for txt in txt_records:
            result.records.append(DNSRecord("TXT", domain, txt))
            if txt.startswith("v=spf1") or "spf" in txt.lower():
                result.spf_record = txt

        # 5. DMARC
        dmarc_records = _nslookup(f"_dmarc.{domain}", "TXT")
        for d in dmarc_records:
            if "v=DMARC1" in d:
                result.dmarc_record = d
                result.records.append(DNSRecord("TXT", f"_dmarc.{domain}", d))

        # 6. Zone transfer attempts
        if result.nameservers:
            for ns in result.nameservers[:3]:  # Try first 3 nameservers
                axfr_records = _attempt_zone_transfer(domain, ns)
                if axfr_records:
                    result.zone_transfer_vulnerable = True
                    result.findings.append(DNSFinding(
                        severity="CRITICAL",
                        title="DNS Zone Transfer Allowed!",
                        description=f"Nameserver {ns} allows AXFR zone transfer requests.",
                        evidence=f"AXFR returned {len(axfr_records)} records",
                        recommendation=(
                            "Disable zone transfers to unauthorized hosts. "
                            "Zone transfers should only be allowed between authorized DNS servers. "
                            "Configure ACLs on your DNS server."
                        )
                    ))
                    break

        # 7. Subdomain enumeration (if deep mode or basic)
        subdomain_list = COMMON_SUBDOMAINS[:30] if not deep else COMMON_SUBDOMAINS
        found_subdomains = self._enumerate_subdomains(domain, subdomain_list)
        result.subdomains = found_subdomains

        # 8. Security checks
        self._check_email_security(result)
        self._check_dnssec(domain, result)
        self._check_wildcard(domain, result)

        return result

    def _enumerate_subdomains(self, domain: str, subdomains: List[str]) -> List[str]:
        """Enumerate common subdomains."""
        found = []
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            ips = _resolve(fqdn)
            if ips:
                found.append(fqdn)
        return found

    def _check_email_security(self, result: DNSReconResult):
        """Check SPF, DMARC, and DKIM configuration."""
        if not result.spf_record:
            result.findings.append(DNSFinding(
                severity="HIGH",
                title="No SPF Record Found",
                description="No SPF (Sender Policy Framework) record found. This allows email spoofing from this domain.",
                recommendation='Add an SPF TXT record: "v=spf1 include:_spf.yourdomain.com ~all"'
            ))
        else:
            # Check for +all (dangerously permissive)
            if "+all" in result.spf_record:
                result.findings.append(DNSFinding(
                    severity="HIGH",
                    title="SPF Record Uses +all (Dangerous)",
                    description="SPF record with '+all' allows ANY server to send mail as this domain.",
                    evidence=f"SPF: {result.spf_record}",
                    recommendation='Replace +all with -all or ~all: "v=spf1 include:... -all"'
                ))
            elif "?all" in result.spf_record:
                result.findings.append(DNSFinding(
                    severity="MEDIUM",
                    title="SPF Record Uses ?all (Permissive)",
                    description="SPF '?all' is neutral and effectively does nothing to prevent spoofing.",
                    evidence=f"SPF: {result.spf_record}",
                    recommendation='Use -all (fail) for strict enforcement or ~all (softfail) as minimum.'
                ))

        if not result.dmarc_record:
            result.findings.append(DNSFinding(
                severity="HIGH",
                title="No DMARC Record Found",
                description="No DMARC policy found. Email authentication failures are not enforced.",
                recommendation='Add: _dmarc.domain TXT "v=DMARC1; p=reject; rua=mailto:dmarc@domain.com"'
            ))
        else:
            # Check DMARC policy
            if "p=none" in result.dmarc_record.lower():
                result.findings.append(DNSFinding(
                    severity="MEDIUM",
                    title="DMARC Policy is 'none' (Monitor Only)",
                    description="DMARC p=none only monitors but does not enforce. Spoofed emails still get delivered.",
                    evidence=f"DMARC: {result.dmarc_record}",
                    recommendation='Change DMARC policy to p=quarantine or p=reject.'
                ))

    def _check_dnssec(self, domain: str, result: DNSReconResult):
        """Check if DNSSEC is enabled."""
        ds_records = _nslookup(domain, "DS")
        dnskey_records = _nslookup(domain, "DNSKEY")

        if ds_records or dnskey_records:
            result.dnssec_enabled = True
            result.findings.append(DNSFinding(
                severity="INFO",
                title="DNSSEC is enabled ✓",
                description="DNSSEC provides cryptographic integrity for DNS responses.",
                recommendation="Ensure DNSSEC keys are rotated regularly."
            ))
        else:
            result.findings.append(DNSFinding(
                severity="MEDIUM",
                title="DNSSEC Not Enabled",
                description="DNSSEC is not configured. DNS responses can be spoofed (DNS poisoning).",
                recommendation="Enable DNSSEC with your domain registrar and DNS provider."
            ))

    def _check_wildcard(self, domain: str, result: DNSReconResult):
        """Check for wildcard DNS that may indicate misconfiguration."""
        random_sub = f"vulnhawk-test-{domain.replace('.', '')[:8]}.{domain}"
        ips = _resolve(random_sub)
        if ips:
            result.findings.append(DNSFinding(
                severity="MEDIUM",
                title="Wildcard DNS Detected",
                description=f"The domain has a wildcard DNS record. All subdomains resolve to an IP.",
                evidence=f"Random subdomain {random_sub} resolved to {', '.join(ips)}",
                recommendation="Review wildcard DNS configuration. Ensure wildcard is intentional."
            ))
