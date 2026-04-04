"""
VulnHawk HTTP Audit Plugin
Checks HTTP security headers, methods, and web server configuration.
"""

import socket
import ssl
import json
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple


@dataclass
class HTTPFinding:
    severity: str
    title: str
    description: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class HTTPAuditResult:
    host: str
    port: int
    url: str = ""
    status_code: int = 0
    server_header: str = ""
    powered_by: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    findings: List[HTTPFinding] = field(default_factory=list)
    methods_allowed: List[str] = field(default_factory=list)
    redirects_to_https: bool = False
    error: str = ""

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")


def _load_header_definitions() -> Dict:
    data_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "vuln_signatures.json"
    )
    try:
        with open(data_path) as f:
            return json.load(f).get("http_security_headers", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _make_raw_request(host: str, port: int, path: str = "/", use_ssl: bool = False,
                       method: str = "GET") -> Tuple[int, Dict[str, str], str]:
    """
    Make a raw HTTP request without third-party libraries.
    Returns (status_code, headers, body).
    """
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: VulnHawk/1.0 Security Scanner\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)

        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        sock.sendall(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 65536:  # cap at 64KB
                break
        sock.close()

        response_str = response.decode("utf-8", errors="ignore")
        lines = response_str.split("\r\n")

        # Parse status line
        status_code = 0
        if lines:
            match = re.match(r"HTTP/\d\.\d (\d+)", lines[0])
            if match:
                status_code = int(match.group(1))

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if line == "":
                break
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()

        # Body
        body = response_str.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in response_str else ""

        return status_code, headers, body

    except Exception as e:
        return 0, {}, str(e)


class HTTPAuditor:
    """Audit HTTP/HTTPS security configuration."""

    SECURITY_HEADERS = [
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "content-security-policy",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    DANGEROUS_METHODS = ["TRACE", "TRACK", "CONNECT", "PUT", "DELETE"]

    def audit(self, host: str, port: int, use_ssl: Optional[bool] = None) -> HTTPAuditResult:
        """Run HTTP security audit."""
        result = HTTPAuditResult(host=host, port=port)

        # Auto-detect SSL if not specified
        if use_ssl is None:
            use_ssl = port in (443, 8443)

        scheme = "https" if use_ssl else "http"
        result.url = f"{scheme}://{host}:{port}/"

        # Make primary request
        status, headers, body = _make_raw_request(host, port, "/", use_ssl)

        if status == 0:
            # Try without SSL if SSL fails
            if use_ssl:
                status, headers, body = _make_raw_request(host, port, "/", False)
                if status != 0:
                    use_ssl = False
                    result.url = f"http://{host}:{port}/"
                else:
                    result.error = "SSL connection failed, fell back to HTTP"

        if status == 0:
            result.error = f"Cannot connect to {host}:{port}"
            return result

        result.status_code = status
        result.headers = {k.lower(): v for k, v in headers.items()}

        # Extract key headers
        result.server_header = headers.get("server", "")
        result.powered_by = headers.get("x-powered-by", "")

        # Check redirects
        if status in (301, 302, 307, 308):
            location = headers.get("location", "")
            if location.startswith("https://"):
                result.redirects_to_https = True

        # Run security checks
        self._check_security_headers(result)
        self._check_info_disclosure(result)
        self._check_http_methods(host, port, use_ssl, result)
        self._check_https_redirect(result, host, port)
        self._check_cookie_security(result)

        return result

    def _check_security_headers(self, result: HTTPAuditResult):
        """Check for missing or misconfigured security headers."""
        header_defs = _load_header_definitions()

        header_checks = {
            "strict-transport-security": {
                "severity": "HIGH",
                "title": "Missing HSTS Header",
                "desc": "HTTP Strict Transport Security (HSTS) is not set. Browsers may use HTTP instead of HTTPS.",
                "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            },
            "x-frame-options": {
                "severity": "MEDIUM",
                "title": "Missing X-Frame-Options",
                "desc": "Without X-Frame-Options, the page can be embedded in iframes enabling clickjacking.",
                "rec": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"
            },
            "x-content-type-options": {
                "severity": "MEDIUM",
                "title": "Missing X-Content-Type-Options",
                "desc": "Without nosniff, browsers may MIME-sniff responses causing content injection.",
                "rec": "Add: X-Content-Type-Options: nosniff"
            },
            "content-security-policy": {
                "severity": "HIGH",
                "title": "Missing Content-Security-Policy",
                "desc": "No CSP defined. This leaves the application vulnerable to XSS attacks.",
                "rec": "Add a CSP header: Content-Security-Policy: default-src 'self'"
            },
            "referrer-policy": {
                "severity": "LOW",
                "title": "Missing Referrer-Policy",
                "desc": "Referrer information may leak to third-party sites.",
                "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin"
            },
        }

        for header_name, check in header_checks.items():
            if header_name not in result.headers:
                result.findings.append(HTTPFinding(
                    severity=check["severity"],
                    title=check["title"],
                    description=check["desc"],
                    recommendation=check["rec"]
                ))
            else:
                # Validate HSTS max-age
                if header_name == "strict-transport-security":
                    val = result.headers[header_name]
                    match = re.search(r"max-age=(\d+)", val, re.IGNORECASE)
                    if match:
                        max_age = int(match.group(1))
                        if max_age < 31536000:
                            result.findings.append(HTTPFinding(
                                severity="MEDIUM",
                                title="HSTS max-age is too short",
                                description=f"HSTS max-age is {max_age}s. Recommended minimum is 31536000 (1 year).",
                                evidence=f"Strict-Transport-Security: {val}",
                                recommendation="Set max-age to at least 31536000."
                            ))

    def _check_info_disclosure(self, result: HTTPAuditResult):
        """Check for information disclosure in headers."""
        if result.server_header:
            # Check for version disclosure
            if re.search(r"[\d\.]", result.server_header):
                result.findings.append(HTTPFinding(
                    severity="LOW",
                    title="Server version disclosed",
                    description=f"The Server header reveals software version information.",
                    evidence=f"Server: {result.server_header}",
                    recommendation="Configure your web server to suppress version information."
                ))
            else:
                result.findings.append(HTTPFinding(
                    severity="INFO",
                    title="Server header present",
                    description="Server header reveals web server technology.",
                    evidence=f"Server: {result.server_header}",
                    recommendation="Consider removing or masking the Server header."
                ))

        if result.powered_by:
            result.findings.append(HTTPFinding(
                severity="LOW",
                title="X-Powered-By header exposes technology stack",
                description="The X-Powered-By header reveals backend technology.",
                evidence=f"X-Powered-By: {result.powered_by}",
                recommendation="Remove X-Powered-By header to reduce attack surface."
            ))

    def _check_http_methods(self, host: str, port: int, use_ssl: bool, result: HTTPAuditResult):
        """Check for dangerous HTTP methods."""
        status, headers, body = _make_raw_request(host, port, "/", use_ssl, "OPTIONS")

        if status == 0:
            return

        allow_header = headers.get("allow", headers.get("public", ""))
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
            result.methods_allowed = methods

            for dangerous in self.DANGEROUS_METHODS:
                if dangerous in methods:
                    result.findings.append(HTTPFinding(
                        severity="HIGH" if dangerous in ("TRACE", "TRACK") else "MEDIUM",
                        title=f"Dangerous HTTP method enabled: {dangerous}",
                        description=(
                            f"The {dangerous} method is allowed. "
                            f"TRACE/TRACK can enable Cross-Site Tracing (XST) attacks. "
                            f"PUT/DELETE allow unauthorized file manipulation."
                        ),
                        evidence=f"Allow: {allow_header}",
                        recommendation=f"Disable the {dangerous} method in your web server configuration."
                    ))

    def _check_https_redirect(self, result: HTTPAuditResult, host: str, port: int):
        """Check if HTTP redirects to HTTPS."""
        if port == 80:
            if not result.redirects_to_https:
                result.findings.append(HTTPFinding(
                    severity="MEDIUM",
                    title="HTTP does not redirect to HTTPS",
                    description="Port 80 (HTTP) is open but does not redirect to HTTPS.",
                    recommendation="Configure a permanent 301 redirect from HTTP to HTTPS."
                ))

    def _check_cookie_security(self, result: HTTPAuditResult):
        """Check cookie security flags."""
        set_cookie = result.headers.get("set-cookie", "")
        if not set_cookie:
            return

        issues = []
        if "secure" not in set_cookie.lower():
            issues.append("missing Secure flag (cookie sent over HTTP)")
        if "httponly" not in set_cookie.lower():
            issues.append("missing HttpOnly flag (accessible via JavaScript)")
        if "samesite" not in set_cookie.lower():
            issues.append("missing SameSite attribute (CSRF risk)")

        for issue in issues:
            result.findings.append(HTTPFinding(
                severity="MEDIUM",
                title=f"Insecure cookie: {issue}",
                description=f"A cookie is {issue}.",
                evidence=f"Set-Cookie: {set_cookie[:100]}",
                recommendation="Set Secure, HttpOnly, and SameSite=Strict on all cookies."
            ))
