#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗║
║  ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ║
║                                                                  ║
║         Modular Network Vulnerability Assessment Framework       ║
║                    Version 1.0 | For Authorized Use Only         ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import argparse
import time
import json
import threading

# Ensure the project root is in path when run directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    from rich.live import Live
    from rich.layout import Layout
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from core.engine import ScanEngine, ScanConfig
from core.reporter import ReportGenerator

console = Console() if RICH_AVAILABLE else None


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

BANNER = """[bold cyan]
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝[/bold cyan]
[dim]  Modular Network Vulnerability Assessment Framework  |  v1.0[/dim]
[bold red]  ⚠  FOR AUTHORIZED PENETRATION TESTING ONLY  ⚠[/bold red]
"""


# ─────────────────────────────────────────────
# OUTPUT HELPERS
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bright_red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim"
}

RISK_ICONS = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪"
}


def print_banner():
    if RICH_AVAILABLE:
        console.print(BANNER)
    else:
        print("VulnHawk - Network Vulnerability Assessment Framework v1.0")


def print_section(title: str):
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")
        console.print(f"[bold cyan]  {title}[/bold cyan]")
        console.print(f"[bold cyan]{'═' * 60}[/bold cyan]")
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")


def print_results(result: dict, verbose: bool = False):
    """Pretty-print scan results to terminal."""

    if not RICH_AVAILABLE:
        _print_results_plain(result)
        return

    target = result.get("target", "")
    ip = result.get("ip", "")
    scan_time = result.get("scan_time", 0)
    summary = result.get("summary", {})

    # ── Summary Panel ──
    risk_level = summary.get("risk_level", "UNKNOWN")
    risk_color = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                  "LOW": "cyan", "MINIMAL": "green"}.get(risk_level, "white")

    summary_text = (
        f"[bold]Target:[/bold]  [cyan]{target}[/cyan]  ([dim]{ip}[/dim])\n"
        f"[bold]Scan Time:[/bold] {scan_time}s\n\n"
        f"[bold]Open Ports:[/bold]      [green]{summary.get('total_open_ports', 0)}[/green]\n"
        f"[bold]Dangerous Ports:[/bold] [yellow]{summary.get('dangerous_ports', 0)}[/yellow]\n"
        f"[bold]Critical Vulns:[/bold]  [bold red]{summary.get('critical_vulns', 0)}[/bold red]\n"
        f"[bold]High Vulns:[/bold]      [bright_red]{summary.get('high_vulns', 0)}[/bright_red]\n"
        f"[bold]Medium Vulns:[/bold]    [yellow]{summary.get('medium_vulns', 0)}[/yellow]\n"
        f"[bold]SSL Issues:[/bold]      [cyan]{summary.get('ssl_issues', 0)}[/cyan]\n"
        f"[bold]HTTP Issues:[/bold]     [cyan]{summary.get('http_issues', 0)}[/cyan]\n\n"
        f"[bold]Risk Score:[/bold]      [{risk_color}]{summary.get('risk_score', 0)}[/{risk_color}]\n"
        f"[bold]Risk Level:[/bold]      [{risk_color}]{risk_level}[/{risk_color}]"
    )
    console.print(Panel(summary_text, title="[bold cyan]⚡ SCAN SUMMARY[/bold cyan]",
                        border_style="cyan", padding=(1, 2)))

    # ── Open Ports Table ──
    open_ports = result.get("open_ports", [])
    if open_ports:
        print_section("PORT SCAN RESULTS")
        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan",
                      border_style="dim")
        table.add_column("PORT", style="green", width=8)
        table.add_column("STATE", width=10)
        table.add_column("SERVICE", width=16)
        table.add_column("BANNER", style="dim", max_width=55)
        table.add_column("LATENCY", width=10)

        for p in open_ports:
            state = p.get("state", "")
            state_markup = f"[bold green]{state.upper()}[/bold green]" if state == "open" else f"[yellow]{state.upper()}[/yellow]"
            table.add_row(
                str(p.get("port", "")),
                Text.from_markup(state_markup),
                p.get("service", ""),
                p.get("banner", "")[:55],
                f"{p.get('latency_ms', 0):.1f}ms"
            )
        console.print(table)

    # ── Dangerous Ports ──
    dangerous = result.get("dangerous_ports", [])
    if dangerous:
        print_section("DANGEROUS EXPOSED PORTS")
        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold yellow",
                      border_style="dim")
        table.add_column("PORT", width=8)
        table.add_column("SERVICE", width=16)
        table.add_column("RISK", width=10)
        table.add_column("REASON", max_width=55)

        for dp in dangerous:
            risk = dp.get("risk", "")
            color = SEVERITY_COLORS.get(risk, "white")
            table.add_row(
                str(dp.get("port", "")),
                dp.get("service", ""),
                Text.from_markup(f"[{color}]{risk}[/{color}]"),
                dp.get("reason", "")
            )
        console.print(table)

    # ── Vulnerabilities ──
    vulns = result.get("vulnerabilities", [])
    if vulns:
        print_section(f"VULNERABILITY FINDINGS ({len(vulns)} found)")
        for v in sorted(vulns, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.get("severity", ""), 4)):
            sev = v.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "white")
            icon = RISK_ICONS.get(sev, "")
            console.print(
                f"  {icon} [{color}]{sev:<8}[/{color}] [bold]{v.get('cve')}[/bold]  "
                f"[cyan]{v.get('service')} {v.get('detected_version')}[/cyan]  "
                f"[dim]port {v.get('port')}[/dim]"
            )
            console.print(f"         [dim]{v.get('description')}[/dim]")
            if v.get("remediation"):
                console.print(f"         [green]↳ Fix: {v.get('remediation')}[/green]")
            console.print()
    else:
        console.print("\n[green]  ✓ No known CVE vulnerabilities detected in scanned services.[/green]")

    # ── SSL/TLS ──
    ssl = result.get("ssl", {})
    if ssl and ssl.get("findings"):
        print_section("SSL/TLS ANALYSIS")
        console.print(
            f"  Protocol: [cyan]{ssl.get('protocol_version', 'N/A')}[/cyan]  |  "
            f"Cipher: [dim]{ssl.get('cipher_suite', 'N/A')}[/dim]"
        )
        cert = ssl.get("certificate", {})
        if cert:
            days = cert.get("days_until_expiry", "N/A")
            expired = cert.get("is_expired", False)
            self_signed = cert.get("is_self_signed", False)
            console.print(
                f"  Cert expiry: {'[red]EXPIRED[/red]' if expired else f'[cyan]{days} days[/cyan]'}  |  "
                f"Self-signed: {'[yellow]YES[/yellow]' if self_signed else '[green]No[/green]'}"
            )
        console.print()
        for f in ssl.get("findings", []):
            sev = f.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "white")
            icon = RISK_ICONS.get(sev, "")
            console.print(f"  {icon} [{color}]{sev:<8}[/{color}] {f.get('title')}")
            if verbose:
                console.print(f"         [dim]{f.get('description')}[/dim]")
                if f.get("recommendation"):
                    console.print(f"         [green]↳ {f.get('recommendation')}[/green]")

    # ── HTTP Audit ──
    http = result.get("http", {})
    if http and http.get("findings"):
        print_section("HTTP SECURITY AUDIT")
        console.print(f"  URL: [cyan]{http.get('url', 'N/A')}[/cyan]  Status: {http.get('status_code', '')}")
        if http.get("server_header"):
            console.print(f"  Server: [dim]{http.get('server_header')}[/dim]")
        console.print()
        for f in http.get("findings", []):
            sev = f.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "white")
            icon = RISK_ICONS.get(sev, "")
            console.print(f"  {icon} [{color}]{sev:<8}[/{color}] {f.get('title')}")
            if verbose and f.get("recommendation"):
                console.print(f"         [green]↳ {f.get('recommendation')}[/green]")

    # ── DNS Recon ──
    dns = result.get("dns", {})
    if dns:
        print_section("DNS RECONNAISSANCE")
        subs = dns.get("subdomains", [])
        if subs:
            console.print(f"  [bold]Subdomains found ({len(subs)}):[/bold]")
            for sub in subs[:15]:
                console.print(f"    [cyan]• {sub}[/cyan]")
            if len(subs) > 15:
                console.print(f"    [dim]... and {len(subs)-15} more[/dim]")
        for f in dns.get("findings", []):
            sev = f.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "white")
            icon = RISK_ICONS.get(sev, "")
            console.print(f"\n  {icon} [{color}]{sev:<8}[/{color}] {f.get('title')}")
            if verbose:
                console.print(f"         [dim]{f.get('description')}[/dim]")

    # ── Remediation Roadmap ──
    remediation = result.get("remediation", [])
    if remediation:
        print_section(f"REMEDIATION ROADMAP (Top {min(10, len(remediation))} Items)")
        table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan",
                      border_style="dim")
        table.add_column("#", width=4)
        table.add_column("TYPE", width=10)
        table.add_column("SEV", width=10)
        table.add_column("ISSUE", max_width=35)
        table.add_column("ACTION", max_width=40)

        for item in remediation[:10]:
            sev = item.get("severity", "")
            color = SEVERITY_COLORS.get(sev, "white")
            table.add_row(
                str(item.get("priority", "")),
                item.get("type", ""),
                Text.from_markup(f"[{color}]{sev}[/{color}]"),
                item.get("title", "")[:35],
                item.get("action", "")[:40]
            )
        console.print(table)


def _print_results_plain(result: dict):
    """Fallback plain text output when rich is not available."""
    print(f"\nTarget: {result.get('target')}")
    print(f"IP: {result.get('ip')}")
    print(f"\nOpen Ports: {len(result.get('open_ports', []))}")
    for p in result.get("open_ports", []):
        print(f"  {p['port']}/tcp  {p['state']}  {p['service']}  {p['banner'][:40]}")

    print(f"\nVulnerabilities: {len(result.get('vulnerabilities', []))}")
    for v in result.get("vulnerabilities", []):
        print(f"  [{v['severity']}] {v['cve']} - {v['service']} {v['detected_version']} (port {v['port']})")

    summary = result.get("summary", {})
    print(f"\nRisk Score: {summary.get('risk_score', 0)}")
    print(f"Risk Level: {summary.get('risk_level', 'N/A')}")


# ─────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnhawk",
        description="VulnHawk — Modular Network Vulnerability Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Quick scan of common ports:
    python vulnhawk.py -t example.com

  Full port scan with all modules:
    python vulnhawk.py -t 192.168.1.1 --full --ssl --http --dns -v

  Top 1000 ports, JSON report only:
    python vulnhawk.py -t example.com --top1000 --format json

  Custom port range:
    python vulnhawk.py -t 10.0.0.1 --ports 80,443,8080,8443

  Custom range scan with HTML report:
    python vulnhawk.py -t 10.0.0.1 --range 1-10000 --format html

  Fast scan, skip SSL/DNS:
    python vulnhawk.py -t example.com --no-ssl --no-http --threads 200

NOTE: Only scan systems you own or have explicit written permission to scan.
        """
    )

    # Target
    parser.add_argument("-t", "--target", required=True,
                        help="Target hostname or IP address")

    # Scan scope
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--common", action="store_true", default=True,
                       help="Scan common ports only (default)")
    scope.add_argument("--top1000", action="store_true",
                       help="Scan top 1000 ports")
    scope.add_argument("--full", action="store_true",
                       help="Full port scan (1-65535). Slower.")
    scope.add_argument("--ports", type=str,
                       help="Comma-separated list of ports (e.g. 22,80,443,8080)")
    scope.add_argument("--range", type=str, dest="port_range",
                       help="Port range (e.g. 1-1024)")

    # Modules
    parser.add_argument("--ssl", action="store_true", default=True,
                        help="Enable SSL/TLS analysis (default: on)")
    parser.add_argument("--no-ssl", action="store_true",
                        help="Disable SSL/TLS analysis")
    parser.add_argument("--http", action="store_true", default=True,
                        help="Enable HTTP security audit (default: on)")
    parser.add_argument("--no-http", action="store_true",
                        help="Disable HTTP audit")
    parser.add_argument("--dns", action="store_true",
                        help="Enable DNS reconnaissance (default: off)")
    parser.add_argument("--no-vuln", action="store_true",
                        help="Skip vulnerability checking")

    # Performance
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Port connection timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=150,
                        help="Max concurrent scan threads (default: 150)")

    # Output
    parser.add_argument("--format", choices=["json", "html", "both", "none"],
                        default="both", help="Report output format (default: both)")
    parser.add_argument("--output-dir", default="reports",
                        help="Directory to save reports (default: ./reports)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output with full descriptions")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner")

    return parser


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # Resolve scan type
    if args.full:
        scan_type = "full"
    elif args.top1000:
        scan_type = "top1000"
    else:
        scan_type = "common"

    # Resolve port list
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
            scan_type = "custom"
        except ValueError:
            console.print("[red]Invalid port list. Use comma-separated integers.[/red]")
            sys.exit(1)

    # Resolve port range
    port_range = None
    if args.port_range:
        try:
            start, end = args.port_range.split("-")
            port_range = (int(start), int(end))
            scan_type = "custom"
        except ValueError:
            console.print("[red]Invalid port range. Use format: start-end (e.g. 1-1024)[/red]")
            sys.exit(1)

    # Build config
    config = ScanConfig(
        target=args.target,
        scan_type=scan_type,
        ports=ports,
        port_range=port_range,
        timeout=args.timeout,
        threads=args.threads,
        check_ssl=not args.no_ssl,
        check_http=not args.no_http,
        check_dns=args.dns,
        check_vulns=not args.no_vuln,
        output_format=args.format,
        output_dir=args.output_dir,
        verbose=args.verbose
    )

    # Progress display
    stage_info = {"stage": "", "detail": ""}
    scan_done = threading.Event()

    def progress_callback(stage, detail=""):
        stage_info["stage"] = stage
        stage_info["detail"] = detail

    # ── Run scan with progress bar ──
    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TaskProgressColumn(),
            console=console,
            transient=True
        ) as progress:
            task = progress.add_task(f"[cyan]Initializing scan of {args.target}...", total=100)

            stages = []
            stages.append("SCAN")
            if config.check_vulns:
                stages.append("VULN")
            if config.check_ssl:
                stages.append("SSL")
            if config.check_http:
                stages.append("HTTP")
            if config.check_dns:
                stages.append("DNS")

            stage_percent = 100 // len(stages)
            completed = 0

            def run_scan():
                nonlocal result
                engine = ScanEngine(config, progress_callback)
                result = engine.run()
                scan_done.set()

            result = {}
            thread = threading.Thread(target=run_scan, daemon=True)
            thread.start()

            stage_messages = {
                "SCAN": f"Port scanning {args.target}...",
                "VULN": "Checking CVE vulnerability database...",
                "SSL": "Analyzing SSL/TLS configuration...",
                "HTTP": "Auditing HTTP security headers...",
                "DNS": "Performing DNS reconnaissance..."
            }

            last_stage = ""
            while not scan_done.is_set():
                current_stage = stage_info["stage"]
                if current_stage and current_stage != last_stage:
                    last_stage = current_stage
                    msg = stage_messages.get(current_stage, current_stage)
                    progress.update(task, description=f"[cyan]{msg}", advance=stage_percent)
                time.sleep(0.1)

            progress.update(task, completed=100, description="[green]Scan complete!")
            thread.join()
    else:
        print(f"Scanning {args.target}...")
        engine = ScanEngine(config, progress_callback)
        result = engine.run()

    # Handle errors
    errors = result.get("errors", [])
    if errors and not result.get("open_ports"):
        if RICH_AVAILABLE:
            console.print(f"\n[bold red]✗ Scan Error:[/bold red] {', '.join(errors)}")
        else:
            print(f"Error: {', '.join(errors)}")
        sys.exit(1)

    # ── Print results ──
    print_results(result, verbose=args.verbose)

    # ── Generate reports ──
    if args.format != "none":
        reporter = ReportGenerator(output_dir=args.output_dir)
        reports_generated = []

        if args.format in ("json", "both"):
            json_path = reporter.generate_json(result)
            reports_generated.append(("JSON", json_path))

        if args.format in ("html", "both"):
            html_path = reporter.generate_html(result)
            reports_generated.append(("HTML", html_path))

        if RICH_AVAILABLE:
            console.print()
            console.print(Rule("[bold cyan]REPORTS GENERATED[/bold cyan]", style="cyan"))
            for fmt, path in reports_generated:
                console.print(f"  [bold green]✓[/bold green] [{fmt}] [cyan]{os.path.abspath(path)}[/cyan]")
            console.print()
        else:
            for fmt, path in reports_generated:
                print(f"Report [{fmt}]: {os.path.abspath(path)}")

    # Exit code: 1 if critical findings, 0 otherwise
    summary = result.get("summary", {})
    if summary.get("critical_vulns", 0) > 0 or summary.get("risk_level") == "CRITICAL":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
