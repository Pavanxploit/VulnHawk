"""
VulnHawk SSL/TLS Analyzer
Inspects SSL/TLS certificates, protocol versions, and cipher suites.
"""

import ssl
import socket
import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
SECURE_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

WEAK_CIPHER_KEYWORDS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "ADH", "AECDH", "CAMELLIA", "SEED", "IDEA", "RC2"
]


@dataclass
class CertificateInfo:
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    san: List[str] = field(default_factory=list)     # Subject Alternative Names
    signature_algorithm: str = ""
    key_bits: int = 0
    is_expired: bool = False
    days_until_expiry: int = 0
    is_self_signed: bool = False
    wildcard: bool = False


@dataclass
class SSLFinding:
    severity: str   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    recommendation: str = ""


@dataclass
class SSLResult:
    host: str
    port: int
    supported: bool = False
    protocol_version: str = ""
    cipher_suite: str = ""
    certificate: Optional[CertificateInfo] = None
    findings: List[SSLFinding] = field(default_factory=list)
    error: str = ""

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity == "HIGH" for f in self.findings)

    @property
    def risk_score(self) -> int:
        scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
        return sum(scores.get(f.severity, 0) for f in self.findings)


class SSLAnalyzer:
    """Analyze SSL/TLS configuration of a host."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def analyze(self, host: str, port: int = 443) -> SSLResult:
        result = SSLResult(host=host, port=port)

        try:
            # Create SSL context
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    result.supported = True
                    result.protocol_version = ssock.version() or "Unknown"
                    result.cipher_suite = ssock.cipher()[0] if ssock.cipher() else "Unknown"

                    # Get certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        result.certificate = self._parse_cert(cert_dict)

            # Run checks
            self._check_protocol(result)
            self._check_certificate(result)
            self._check_cipher(result)

        except ssl.SSLError as e:
            result.error = f"SSL Error: {str(e)}"
            result.supported = False
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result.error = f"Connection error: {str(e)}"
            result.supported = False

        # Also test for weak protocol support
        if result.supported:
            self._test_weak_protocols(host, port, result)

        return result

    def _parse_cert(self, cert_dict: dict) -> CertificateInfo:
        info = CertificateInfo()

        # Subject
        if "subject" in cert_dict:
            for item in cert_dict["subject"]:
                for k, v in item:
                    info.subject[k] = v

        # Issuer
        if "issuer" in cert_dict:
            for item in cert_dict["issuer"]:
                for k, v in item:
                    info.issuer[k] = v

        # Serial number
        info.serial_number = str(cert_dict.get("serialNumber", ""))

        # Validity dates
        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")

        if not_before_str:
            try:
                info.not_before = datetime.datetime.strptime(
                    not_before_str, "%b %d %H:%M:%S %Y %Z"
                )
            except ValueError:
                pass

        if not_after_str:
            try:
                info.not_after = datetime.datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                )
                now = datetime.datetime.utcnow()
                info.is_expired = info.not_after < now
                info.days_until_expiry = (info.not_after - now).days
            except ValueError:
                pass

        # SANs
        if "subjectAltName" in cert_dict:
            info.san = [v for (t, v) in cert_dict["subjectAltName"] if t == "DNS"]

        # Self-signed check
        info.is_self_signed = info.subject == info.issuer

        # Wildcard check
        cn = info.subject.get("commonName", "")
        info.wildcard = cn.startswith("*.")
        if any(san.startswith("*.") for san in info.san):
            info.wildcard = True

        return info

    def _check_protocol(self, result: SSLResult):
        """Check protocol version for weaknesses."""
        proto = result.protocol_version

        if proto in ("SSLv2", "SSLv3"):
            result.findings.append(SSLFinding(
                severity="CRITICAL",
                title=f"Obsolete protocol: {proto}",
                description=f"{proto} is completely broken and deprecated (POODLE, DROWN attacks).",
                recommendation="Disable SSLv2/SSLv3 immediately. Use TLS 1.2 or 1.3."
            ))
        elif proto == "TLSv1":
            result.findings.append(SSLFinding(
                severity="HIGH",
                title="Deprecated protocol: TLS 1.0",
                description="TLS 1.0 is deprecated (RFC 8996). Vulnerable to BEAST and POODLE attacks.",
                recommendation="Upgrade to TLS 1.2 or TLS 1.3."
            ))
        elif proto == "TLSv1.1":
            result.findings.append(SSLFinding(
                severity="HIGH",
                title="Deprecated protocol: TLS 1.1",
                description="TLS 1.1 is deprecated (RFC 8996) and lacks modern security features.",
                recommendation="Upgrade to TLS 1.2 or TLS 1.3."
            ))
        elif proto == "TLSv1.2":
            result.findings.append(SSLFinding(
                severity="INFO",
                title="Protocol: TLS 1.2",
                description="TLS 1.2 is acceptable but TLS 1.3 is preferred.",
                recommendation="Consider upgrading to TLS 1.3 for better security and performance."
            ))
        elif proto == "TLSv1.3":
            result.findings.append(SSLFinding(
                severity="INFO",
                title="Protocol: TLS 1.3 ✓",
                description="TLS 1.3 is the most secure TLS version available.",
                recommendation="No action needed."
            ))

    def _check_certificate(self, result: SSLResult):
        """Check certificate for issues."""
        cert = result.certificate
        if not cert:
            return

        # Expired cert
        if cert.is_expired:
            result.findings.append(SSLFinding(
                severity="CRITICAL",
                title="Certificate is EXPIRED",
                description=f"The SSL certificate expired on {cert.not_after}.",
                recommendation="Renew the certificate immediately. Browsers will show security warnings."
            ))
        elif cert.days_until_expiry <= 7:
            result.findings.append(SSLFinding(
                severity="CRITICAL",
                title=f"Certificate expires in {cert.days_until_expiry} days",
                description="Certificate is critically close to expiry.",
                recommendation="Renew the certificate immediately."
            ))
        elif cert.days_until_expiry <= 30:
            result.findings.append(SSLFinding(
                severity="HIGH",
                title=f"Certificate expires in {cert.days_until_expiry} days",
                description="Certificate expiry approaching.",
                recommendation="Renew the certificate soon."
            ))
        elif cert.days_until_expiry <= 90:
            result.findings.append(SSLFinding(
                severity="MEDIUM",
                title=f"Certificate expires in {cert.days_until_expiry} days",
                description="Certificate expiry is within 90 days.",
                recommendation="Plan certificate renewal."
            ))
        else:
            result.findings.append(SSLFinding(
                severity="INFO",
                title=f"Certificate valid for {cert.days_until_expiry} days",
                description="Certificate expiry is not imminent.",
                recommendation=""
            ))

        # Self-signed
        if cert.is_self_signed:
            result.findings.append(SSLFinding(
                severity="HIGH",
                title="Self-signed certificate",
                description="Certificate is signed by itself, not by a trusted CA. Browsers will show security warnings.",
                recommendation="Replace with a certificate from a trusted Certificate Authority (Let's Encrypt, DigiCert, etc.)"
            ))

        # Weak signature algorithm
        sig_alg = cert.signature_algorithm.upper()
        if "MD5" in sig_alg:
            result.findings.append(SSLFinding(
                severity="CRITICAL",
                title="Certificate uses MD5 signature",
                description="MD5 is cryptographically broken and allows certificate forgery.",
                recommendation="Replace certificate with one using SHA-256 or SHA-384."
            ))
        elif "SHA1" in sig_alg:
            result.findings.append(SSLFinding(
                severity="HIGH",
                title="Certificate uses SHA-1 signature",
                description="SHA-1 is deprecated and major browsers have removed support.",
                recommendation="Replace certificate with one using SHA-256 or SHA-384."
            ))

    def _check_cipher(self, result: SSLResult):
        """Check cipher suite for weaknesses."""
        cipher = result.cipher_suite.upper()

        for weak in WEAK_CIPHER_KEYWORDS:
            if weak.upper() in cipher:
                result.findings.append(SSLFinding(
                    severity="HIGH",
                    title=f"Weak cipher suite: {result.cipher_suite}",
                    description=f"The cipher suite contains '{weak}' which is considered weak or broken.",
                    recommendation="Configure server to prefer ECDHE+AESGCM or ChaCha20-Poly1305 suites."
                ))
                break

    def _test_weak_protocols(self, host: str, port: int, result: SSLResult):
        """Test if server accepts deprecated protocol versions."""
        weak_protos_found = []

        for proto_const, proto_name in [
            (ssl.PROTOCOL_TLS_CLIENT, "TLSv1"),
        ]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1

                with socket.create_connection((host, port), timeout=2.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        weak_protos_found.append("TLS 1.0")
            except (ssl.SSLError, OSError, AttributeError):
                pass

        for proto_name in weak_protos_found:
            result.findings.append(SSLFinding(
                severity="HIGH",
                title=f"Server accepts {proto_name}",
                description=f"The server accepts connections using the deprecated {proto_name} protocol.",
                recommendation=f"Disable {proto_name} in your server configuration."
            ))
