"""
VulnHawk Report Generator
Generates JSON and HTML security assessment reports.
"""

import json
import os
import datetime
from typing import Dict, Any, List
from dataclasses import asdict


REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnHawk Security Report - {target}</title>
<style>
  :root {{
    --bg: #0a0e1a;
    --card: #111827;
    --border: #1f2d3d;
    --accent: #00d4ff;
    --green: #00ff88;
    --red: #ff3366;
    --orange: #ff8c00;
    --yellow: #ffd700;
    --text: #e2e8f0;
    --muted: #64748b;
    --critical: #ff1744;
    --high: #ff5722;
    --medium: #ff9800;
    --low: #2196f3;
    --info: #607d8b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Courier New', Courier, monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 20px;
  }}
  .header {{
    border: 1px solid var(--accent);
    padding: 30px;
    margin-bottom: 30px;
    position: relative;
    background: linear-gradient(135deg, #0a0e1a 0%, #111827 100%);
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent), var(--green));
  }}
  .header h1 {{
    font-size: 2rem;
    color: var(--accent);
    letter-spacing: 4px;
    text-transform: uppercase;
  }}
  .header .subtitle {{
    color: var(--muted);
    margin-top: 5px;
    font-size: 0.85rem;
    letter-spacing: 2px;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
  }}
  .meta-card {{
    background: var(--card);
    border: 1px solid var(--border);
    padding: 20px;
    text-align: center;
  }}
  .meta-card .value {{
    font-size: 2.5rem;
    font-weight: bold;
    display: block;
  }}
  .meta-card .label {{
    color: var(--muted);
    font-size: 0.75rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-top: 5px;
  }}
  .critical {{ color: var(--critical) !important; }}
  .high {{ color: var(--high) !important; }}
  .medium {{ color: var(--medium) !important; }}
  .low {{ color: var(--low) !important; }}
  .info {{ color: var(--info) !important; }}
  .section {{
    margin-bottom: 30px;
  }}
  .section-title {{
    color: var(--accent);
    font-size: 1rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 20px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }}
  th {{
    background: var(--border);
    color: var(--accent);
    padding: 10px 15px;
    text-align: left;
    letter-spacing: 1px;
    font-size: 0.75rem;
    text-transform: uppercase;
  }}
  td {{
    padding: 10px 15px;
    border-bottom: 1px solid var(--border);
  }}
  tr:hover td {{ background: rgba(0, 212, 255, 0.03); }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    font-size: 0.7rem;
    font-weight: bold;
    letter-spacing: 1px;
    border-radius: 2px;
  }}
  .badge-critical {{ background: #ff1744; color: white; }}
  .badge-high {{ background: #ff5722; color: white; }}
  .badge-medium {{ background: #ff9800; color: black; }}
  .badge-low {{ background: #2196f3; color: white; }}
  .badge-info {{ background: #607d8b; color: white; }}
  .badge-open {{ background: #00ff88; color: black; }}
  .finding-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 3px solid;
    padding: 15px 20px;
    margin-bottom: 12px;
  }}
  .finding-card.critical {{ border-left-color: var(--critical); }}
  .finding-card.high {{ border-left-color: var(--high); }}
  .finding-card.medium {{ border-left-color: var(--medium); }}
  .finding-card.low {{ border-left-color: var(--low); }}
  .finding-card.info {{ border-left-color: var(--info); }}
  .finding-title {{
    font-weight: bold;
    margin-bottom: 5px;
  }}
  .finding-desc {{
    color: var(--muted);
    font-size: 0.85rem;
    margin-bottom: 8px;
  }}
  .finding-rec {{
    color: var(--green);
    font-size: 0.8rem;
    padding: 5px 10px;
    background: rgba(0, 255, 136, 0.05);
    border-left: 2px solid var(--green);
  }}
  .evidence {{
    font-family: monospace;
    background: rgba(0,0,0,0.3);
    padding: 5px 10px;
    font-size: 0.8rem;
    color: var(--yellow);
    margin: 5px 0;
  }}
  .risk-bar {{
    height: 4px;
    background: var(--border);
    margin: 5px 0;
    border-radius: 2px;
    overflow: hidden;
  }}
  .risk-fill {{
    height: 100%;
    background: linear-gradient(90deg, var(--green), var(--yellow), var(--red));
  }}
  .footer {{
    text-align: center;
    color: var(--muted);
    font-size: 0.75rem;
    padding: 20px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
    letter-spacing: 2px;
  }}
  .open-port {{ color: var(--green); }}
  .filtered-port {{ color: var(--yellow); }}
  .tag {{
    display: inline-block;
    padding: 1px 6px;
    background: rgba(0, 212, 255, 0.1);
    border: 1px solid rgba(0, 212, 255, 0.3);
    font-size: 0.7rem;
    color: var(--accent);
    margin: 2px;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ VulnHawk</h1>
  <div class="subtitle">SECURITY ASSESSMENT REPORT</div>
  <div style="margin-top:15px; color: var(--muted); font-size:0.8rem;">
    <span>TARGET: <strong style="color:var(--accent)">{target}</strong></span>&nbsp;&nbsp;|&nbsp;&nbsp;
    <span>IP: <strong style="color:var(--accent)">{ip}</strong></span>&nbsp;&nbsp;|&nbsp;&nbsp;
    <span>SCAN DATE: <strong style="color:var(--accent)">{scan_date}</strong></span>&nbsp;&nbsp;|&nbsp;&nbsp;
    <span>DURATION: <strong style="color:var(--accent)">{scan_time}s</strong></span>
  </div>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <span class="value critical">{critical}</span>
    <span class="label">Critical</span>
  </div>
  <div class="meta-card">
    <span class="value high">{high}</span>
    <span class="label">High</span>
  </div>
  <div class="meta-card">
    <span class="value medium">{medium}</span>
    <span class="label">Medium</span>
  </div>
  <div class="meta-card">
    <span class="value low">{low}</span>
    <span class="label">Low</span>
  </div>
  <div class="meta-card">
    <span class="value" style="color:var(--green)">{open_ports}</span>
    <span class="label">Open Ports</span>
  </div>
  <div class="meta-card">
    <span class="value" style="color:var(--accent)">{risk_score}</span>
    <span class="label">Risk Score</span>
  </div>
</div>

{port_section}

{vuln_section}

{ssl_section}

{http_section}

{dns_section}

{remediation_section}

<div class="footer">
  VULNHAWK SECURITY FRAMEWORK v1.0 &nbsp;|&nbsp; GENERATED {scan_date} &nbsp;|&nbsp;
  FOR AUTHORIZED USE ONLY
</div>
</body>
</html>
"""


class ReportGenerator:
    """Generate security assessment reports."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_json(self, data: Dict[str, Any], filename: str = None) -> str:
        """Generate JSON report."""
        if not filename:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target = data.get("target", "unknown").replace(".", "_")
            filename = f"vulnhawk_{target}_{ts}.json"

        filepath = os.path.join(self.output_dir, filename)

        # Make data JSON-serializable
        serializable = self._make_serializable(data)

        with open(filepath, "w") as f:
            json.dump(serializable, f, indent=2, default=str)

        return filepath

    def generate_html(self, data: Dict[str, Any], filename: str = None) -> str:
        """Generate HTML report."""
        if not filename:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            target = data.get("target", "unknown").replace(".", "_")
            filename = f"vulnhawk_{target}_{ts}.html"

        filepath = os.path.join(self.output_dir, filename)

        # Build HTML sections
        html = self._render_html(data)

        with open(filepath, "w") as f:
            f.write(html)

        return filepath

    def _make_serializable(self, obj):
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(i) for i in obj]
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif hasattr(obj, "__dict__"):
            return self._make_serializable(obj.__dict__)
        return obj

    def _severity_badge(self, severity: str) -> str:
        return f'<span class="badge badge-{severity.lower()}">{severity}</span>'

    def _render_html(self, data: Dict) -> str:
        target = data.get("target", "Unknown")
        ip = data.get("ip", "Unknown")
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        scan_time = data.get("scan_time", 0)

        # Counts
        vulns = data.get("vulnerabilities", [])
        critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        high = sum(1 for v in vulns if v.get("severity") == "HIGH")
        medium = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
        low = sum(1 for v in vulns if v.get("severity") == "LOW")
        open_ports = len(data.get("open_ports", []))
        risk_score = data.get("risk_score", 0)

        # --- Port Section ---
        port_rows = ""
        for p in data.get("open_ports", []):
            state_class = "open-port" if p.get("state") == "open" else "filtered-port"
            banner = p.get("banner", "")[:60]
            port_rows += f"""
            <tr>
              <td class="{state_class}">{p.get('port')}</td>
              <td>{p.get('protocol', 'tcp').upper()}</td>
              <td><span class="badge badge-open">{p.get('state', '').upper()}</span></td>
              <td>{p.get('service', '')}</td>
              <td><span style="color:#64748b;font-size:0.8em">{banner}</span></td>
              <td>{p.get('latency_ms', 0):.1f} ms</td>
            </tr>"""

        port_section = f"""
        <div class="section">
          <div class="section-title">[ PORT SCAN RESULTS ]</div>
          <table>
            <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th><th>Latency</th></tr>
            {port_rows if port_rows else '<tr><td colspan="6" style="color:#64748b">No open ports detected</td></tr>'}
          </table>
        </div>"""

        # --- Vulnerability Section ---
        vuln_cards = ""
        for v in sorted(vulns, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", ""), 4)):
            sev = v.get("severity", "info").lower()
            vuln_cards += f"""
            <div class="finding-card {sev}">
              <div class="finding-title">
                {self._severity_badge(v.get('severity',''))}
                &nbsp; {v.get('cve', 'N/A')} — {v.get('service', '')} v{v.get('detected_version', '')}
                <span style="color:var(--muted);font-size:0.8rem"> on port {v.get('port', '')}</span>
              </div>
              <div class="finding-desc">{v.get('description', '')}</div>
              {"<div class='finding-rec'>💡 " + v.get('remediation', '') + "</div>" if v.get('remediation') else ""}
            </div>"""

        vuln_section = f"""
        <div class="section">
          <div class="section-title">[ VULNERABILITY FINDINGS ]</div>
          {vuln_cards if vuln_cards else '<div style="color:#64748b">No CVE-based vulnerabilities detected</div>'}
        </div>"""

        # --- Dangerous Ports Section ---
        danger_rows = ""
        for dp in data.get("dangerous_ports", []):
            danger_rows += f"""
            <tr>
              <td class="open-port">{dp.get('port')}</td>
              <td>{dp.get('service', '')}</td>
              <td>{self._severity_badge(dp.get('risk', ''))}</td>
              <td style="color:var(--muted);font-size:0.85em">{dp.get('reason', '')}</td>
            </tr>"""

        # --- SSL Section ---
        ssl_data = data.get("ssl", {})
        ssl_cards = ""
        for f in ssl_data.get("findings", []):
            sev = f.get("severity", "info").lower()
            ssl_cards += f"""
            <div class="finding-card {sev}">
              <div class="finding-title">{self._severity_badge(f.get('severity',''))} &nbsp; {f.get('title','')}</div>
              <div class="finding-desc">{f.get('description','')}</div>
              {"<div class='finding-rec'>💡 " + f.get('recommendation','') + "</div>" if f.get('recommendation') else ""}
            </div>"""

        ssl_section = ""
        if ssl_data:
            proto = ssl_data.get("protocol_version", "N/A")
            cipher = ssl_data.get("cipher_suite", "N/A")
            cert = ssl_data.get("certificate", {})
            days = cert.get("days_until_expiry", "N/A") if cert else "N/A"
            ssl_section = f"""
            <div class="section">
              <div class="section-title">[ SSL/TLS ANALYSIS ]</div>
              <table style="margin-bottom:15px">
                <tr><th>Protocol</th><th>Cipher Suite</th><th>Cert Expiry</th><th>Self-Signed</th></tr>
                <tr>
                  <td>{proto}</td><td>{cipher}</td>
                  <td>{days} days</td>
                  <td>{"⚠ YES" if cert and cert.get("is_self_signed") else "No"}</td>
                </tr>
              </table>
              {ssl_cards if ssl_cards else '<div style="color:#64748b">No SSL/TLS findings</div>'}
            </div>"""

        # --- HTTP Section ---
        http_data = data.get("http", {})
        http_cards = ""
        for f in http_data.get("findings", []):
            sev = f.get("severity", "info").lower()
            evidence = f.get("evidence", "")
            http_cards += f"""
            <div class="finding-card {sev}">
              <div class="finding-title">{self._severity_badge(f.get('severity',''))} &nbsp; {f.get('title','')}</div>
              <div class="finding-desc">{f.get('description','')}</div>
              {f"<div class='evidence'>{evidence}</div>" if evidence else ""}
              {"<div class='finding-rec'>💡 " + f.get('recommendation','') + "</div>" if f.get('recommendation') else ""}
            </div>"""

        http_section = ""
        if http_data:
            http_section = f"""
            <div class="section">
              <div class="section-title">[ HTTP SECURITY AUDIT ]</div>
              <div style="color:var(--muted);font-size:0.8rem;margin-bottom:10px">
                URL: {http_data.get('url','')} &nbsp;|&nbsp;
                Status: {http_data.get('status_code','')} &nbsp;|&nbsp;
                Server: {http_data.get('server_header','N/A')}
              </div>
              {http_cards if http_cards else '<div style="color:#64748b">No HTTP findings</div>'}
            </div>"""

        # --- DNS Section ---
        dns_data = data.get("dns", {})
        dns_cards = ""
        for f in dns_data.get("findings", []):
            sev = f.get("severity", "info").lower()
            dns_cards += f"""
            <div class="finding-card {sev}">
              <div class="finding-title">{self._severity_badge(f.get('severity',''))} &nbsp; {f.get('title','')}</div>
              <div class="finding-desc">{f.get('description','')}</div>
              {"<div class='finding-rec'>💡 " + f.get('recommendation','') + "</div>" if f.get('recommendation') else ""}
            </div>"""

        dns_section = ""
        if dns_data:
            subdomains = dns_data.get("subdomains", [])
            sub_tags = "".join([f'<span class="tag">{s}</span>' for s in subdomains[:20]])
            dns_section = f"""
            <div class="section">
              <div class="section-title">[ DNS RECONNAISSANCE ]</div>
              <div style="margin-bottom:15px">
                <div style="color:var(--muted);font-size:0.8rem;margin-bottom:8px">DISCOVERED SUBDOMAINS ({len(subdomains)}):</div>
                {sub_tags if sub_tags else '<span style="color:#64748b">None found</span>'}
              </div>
              {dns_cards if dns_cards else '<div style="color:#64748b">No DNS security issues detected</div>'}
            </div>"""

        # --- Remediation Section ---
        remediation = data.get("remediation", [])
        rem_rows = ""
        for item in remediation[:20]:
            rem_rows += f"""
            <tr>
              <td style="color:var(--muted)">{item.get('priority','')}</td>
              <td><span class="tag">{item.get('type','')}</span></td>
              <td>{self._severity_badge(item.get('severity',''))}</td>
              <td>{item.get('title','')}</td>
              <td style="color:var(--green);font-size:0.8em">{item.get('action','')}</td>
            </tr>"""

        remediation_section = f"""
        <div class="section">
          <div class="section-title">[ REMEDIATION ROADMAP ]</div>
          <table>
            <tr><th>#</th><th>Type</th><th>Severity</th><th>Issue</th><th>Action Required</th></tr>
            {rem_rows if rem_rows else '<tr><td colspan="5" style="color:#64748b">No remediation items</td></tr>'}
          </table>
        </div>"""

        return REPORT_HTML_TEMPLATE.format(
            target=target, ip=ip, scan_date=scan_date, scan_time=scan_time,
            critical=critical, high=high, medium=medium, low=low,
            open_ports=open_ports, risk_score=risk_score,
            port_section=port_section,
            vuln_section=vuln_section,
            ssl_section=ssl_section,
            http_section=http_section,
            dns_section=dns_section,
            remediation_section=remediation_section
        )
