#!/usr/bin/env python3
"""
recon-arsenal :: osint.py
OSINT automation: WHOIS, DNS history, email harvesting, subdomain enumeration,
Google dorking queries, Shodan summary, certificate transparency.
Authorized use only.
"""

import argparse
import asyncio
import json
import re
import socket
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.BLUE}
╔══════════════════════════════════════════════════╗
║         recon-arsenal :: osint v1.0              ║
║     Open Source Intelligence — Auth Use Only     ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# ──────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────

@dataclass
class OsintReport:
    domain: str
    timestamp: str = ""
    whois: dict = field(default_factory=dict)
    dns: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    dorks: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ──────────────────────────────────────────────────
# Modules
# ──────────────────────────────────────────────────

class OSINTEngine:
    def __init__(self, domain: str, output: Optional[str], shodan_key: Optional[str]):
        self.domain = self._normalize(domain)
        self.output = output
        self.shodan_key = shodan_key
        self.report = OsintReport(
            domain=self.domain,
            timestamp=datetime.utcnow().isoformat()
        )

    def _normalize(self, d: str) -> str:
        d = d.strip().lower()
        if d.startswith(("http://","https://")):
            d = urlparse(d).netloc
        return d.lstrip("www.")

    # ── DNS Resolution ──────────────────────────────
    async def resolve_dns(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ DNS ][/bold cyan]")
        records = {}
        rtypes = ["A","AAAA","MX","NS","TXT","SOA","CNAME","CAA"]

        for rtype in rtypes:
            try:
                url = f"https://dns.google/resolve?name={self.domain}&type={rtype}"
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    data = await r.json()
                    answers = data.get("Answer", [])
                    if answers:
                        records[rtype] = [a.get("data","") for a in answers]
                        console.print(f"  [green]{rtype:6}[/green] {records[rtype]}")
            except Exception:
                pass

        # Also try direct resolution
        try:
            ips = socket.gethostbyname_ex(self.domain)
            self.report.ips = ips[2]
        except Exception:
            pass

        self.report.dns = records

    # ── Certificate Transparency ─────────────────────
    async def cert_transparency(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ Certificate Transparency ][/bold cyan]")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as r:
                entries = await r.json(content_type=None)
                seen = set()
                subs = []
                for e in entries:
                    names = e.get("name_value","").split("\n")
                    for n in names:
                        n = n.strip().lstrip("*.").lower()
                        if n.endswith(self.domain) and n not in seen:
                            seen.add(n)
                            subs.append(n)
                            self.report.certificates.append({
                                "name": n,
                                "issuer": e.get("issuer_name",""),
                                "logged": e.get("entry_timestamp",""),
                            })
                self.report.subdomains = sorted(list(set(
                    self.report.subdomains + subs
                )))
                console.print(f"  Found [green]{len(subs)}[/green] names via crt.sh")
        except Exception as e:
            console.print(f"  [dim red]crt.sh error: {e}[/dim red]")

    # ── HackerTarget Subdomain Enum ──────────────────
    async def hackertarget_subdomains(self, session: aiohttp.ClientSession):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as r:
                text = await r.text()
                if "error" not in text.lower():
                    for line in text.splitlines():
                        parts = line.split(",")
                        if parts:
                            sub = parts[0].strip()
                            if sub.endswith(self.domain):
                                if sub not in self.report.subdomains:
                                    self.report.subdomains.append(sub)
            console.print(f"  Total unique subdomains: [green]{len(self.report.subdomains)}[/green]")
        except Exception:
            pass

    # ── Email Harvesting (from common patterns) ───────
    async def harvest_emails(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ Email Patterns ][/bold cyan]")
        # Check common email-exposure endpoints
        endpoints = [
            f"https://{self.domain}/humans.txt",
            f"https://{self.domain}/security.txt",
            f"https://{self.domain}/.well-known/security.txt",
        ]
        email_re = re.compile(
            r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\." + re.escape(self.domain),
            re.I
        )
        generic_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)

        found = set()
        for ep in endpoints:
            try:
                async with session.get(ep, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    if r.status == 200:
                        text = await r.text()
                        found.update(email_re.findall(text))
                        found.update(generic_re.findall(text))
            except Exception:
                pass

        # Generate educated guesses from DNS MX
        mx = self.report.dns.get("MX", [])
        common_prefixes = ["security", "admin", "webmaster", "contact",
                           "info", "support", "abuse", "hostmaster"]
        guesses = [f"{p}@{self.domain}" for p in common_prefixes]

        self.report.emails = sorted(list(found)) + guesses
        console.print(f"  Harvested: {len(found)} | Common guesses: {len(guesses)}")
        for e in sorted(found):
            console.print(f"  [green]{e}[/green]")

    # ── WHOIS (via RDAP) ──────────────────────────────
    async def whois_rdap(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ WHOIS / RDAP ][/bold cyan]")
        try:
            url = f"https://rdap.org/domain/{self.domain}"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                data = await r.json(content_type=None)
                info = {
                    "name": data.get("ldhName", self.domain),
                    "status": data.get("status", []),
                    "registered": next(
                        (e.get("eventDate","") for e in data.get("events",[])
                         if e.get("eventAction")=="registration"), ""
                    ),
                    "expires": next(
                        (e.get("eventDate","") for e in data.get("events",[])
                         if e.get("eventAction")=="expiration"), ""
                    ),
                    "nameservers": [ns.get("ldhName","") for ns in data.get("nameservers",[])],
                    "registrar": next(
                        (e.get("vcardArray","") for e in data.get("entities",[])
                         if "registrar" in e.get("roles",[])), ""
                    ),
                }
                self.report.whois = info
                t = Table(show_header=False, box=None, padding=(0,2))
                for k, v in info.items():
                    t.add_row(f"[dim]{k}[/dim]", str(v))
                console.print(t)
        except Exception as e:
            console.print(f"  [dim red]RDAP error: {e}[/dim red]")

    # ── Technology Fingerprinting ─────────────────────
    async def fingerprint(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ Technology Fingerprinting ][/bold cyan]")
        signatures = {
            "WordPress": [r"wp-content", r"wp-includes", r"/xmlrpc.php"],
            "Drupal": [r"Drupal", r"/sites/default/files"],
            "Joomla": [r"/components/com_", r"Joomla"],
            "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
            "Django": [r"csrfmiddlewaretoken", r"django"],
            "Ruby on Rails": [r"_rails_session", r"X-Powered-By: Phusion"],
            "ASP.NET": [r"__VIEWSTATE", r"ASP.NET_SessionId", r"X-Powered-By: ASP.NET"],
            "PHP": [r"X-Powered-By: PHP", r"PHPSESSID"],
            "Nginx": [r"Server: nginx"],
            "Apache": [r"Server: Apache"],
            "Cloudflare": [r"cf-ray", r"cloudflare"],
            "React": [r"__REACT_DEVTOOLS", r"react.development"],
            "jQuery": [r"jquery.min.js", r"jquery-"],
            "Bootstrap": [r"bootstrap.min.css", r"bootstrap.min.js"],
        }
        try:
            url = f"https://{self.domain}"
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=True) as r:
                body = await r.text(errors="ignore")
                headers_str = str(dict(r.headers))
                combined = body + headers_str
                found = []
                for tech, patterns in signatures.items():
                    if any(re.search(p, combined, re.I) for p in patterns):
                        found.append(tech)
                self.report.technologies = found
                console.print(f"  Detected: [green]{', '.join(found) or 'None'}[/green]")
                # Grab interesting headers
                interesting = ["server","x-powered-by","x-generator","x-frame-options",
                               "content-security-policy","strict-transport-security",
                               "x-content-type-options","access-control-allow-origin"]
                hdrs = {k: v for k, v in r.headers.items() if k.lower() in interesting}
                self.report.metadata["headers"] = hdrs
                if hdrs:
                    t = Table(show_header=False, box=None)
                    for k, v in hdrs.items():
                        t.add_row(f"[dim]{k}[/dim]", v)
                    console.print(t)
        except Exception as e:
            console.print(f"  [dim red]Fingerprint error: {e}[/dim red]")

    # ── Google Dorks Generator ────────────────────────
    def generate_dorks(self):
        console.print("\n[bold cyan][ Google Dorks ][/bold cyan]")
        d = self.domain
        dorks = [
            f'site:{d} filetype:pdf',
            f'site:{d} filetype:xls OR filetype:xlsx OR filetype:csv',
            f'site:{d} filetype:doc OR filetype:docx',
            f'site:{d} inurl:admin',
            f'site:{d} inurl:login',
            f'site:{d} inurl:dashboard',
            f'site:{d} inurl:api',
            f'site:{d} inurl:swagger OR inurl:openapi',
            f'site:{d} inurl:config OR inurl:.env',
            f'site:{d} inurl:backup OR inurl:bak OR inurl:.sql',
            f'site:{d} inurl:upload OR inurl:file',
            f'site:{d} "Index of /"',
            f'site:{d} intext:"sql syntax" OR intext:"mysql_fetch"',
            f'site:{d} intext:"error" intext:"stack trace"',
            f'site:github.com "{d}" password OR secret OR key OR token',
            f'site:pastebin.com "{d}"',
            f'site:trello.com "{d}"',
            f'"{d}" filetype:log',
            f'"{d}" intext:"BEGIN RSA PRIVATE KEY"',
            f'inurl:"{d}" ext:php intitle:"phpMyAdmin"',
        ]
        self.report.dorks = dorks
        for dork in dorks:
            console.print(f"  [dim]»[/dim] {dork}")

    # ── IP Enrichment (ip-api.com) ────────────────────
    async def enrich_ips(self, session: aiohttp.ClientSession):
        console.print("\n[bold cyan][ IP Geolocation ][/bold cyan]")
        enriched = []
        for ip in self.report.ips[:5]:  # limit free API
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=6)) as r:
                    data = await r.json()
                    enriched.append({"ip": ip, **data})
                    console.print(
                        f"  [green]{ip}[/green]  {data.get('country','')} / "
                        f"{data.get('city','')}  ISP: {data.get('isp','')}"
                    )
            except Exception:
                pass
        self.report.metadata["ip_geo"] = enriched

    # ── Save Report ───────────────────────────────────
    def save_report(self):
        if not self.output:
            return
        p = Path(self.output)
        p.write_text(json.dumps(self.report.__dict__, indent=2, default=str))
        console.print(f"\n[green]Report saved → {p}[/green]")

    async def run_all(self):
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            await self.whois_rdap(session)
            await self.resolve_dns(session)
            await self.cert_transparency(session)
            await self.hackertarget_subdomains(session)
            await self.harvest_emails(session)
            await self.fingerprint(session)
            await self.enrich_ips(session)
            self.generate_dorks()

        # Summary
        console.print(Panel(
            f"[bold]Domain:[/bold] {self.domain}\n"
            f"[bold]Subdomains:[/bold] {len(self.report.subdomains)}\n"
            f"[bold]IPs:[/bold] {', '.join(self.report.ips)}\n"
            f"[bold]Emails:[/bold] {len(self.report.emails)}\n"
            f"[bold]Technologies:[/bold] {', '.join(self.report.technologies)}\n"
            f"[bold]DNS Records:[/bold] {list(self.report.dns.keys())}",
            title="OSINT Summary",
            border_style="cyan",
        ))
        self.save_report()


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="OSINT toolkit — authorized use only")
    p.add_argument("domain", help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", help="Save JSON report to file")
    p.add_argument("--shodan-key", help="Shodan API key for IP enrichment")
    args = p.parse_args()

    engine = OSINTEngine(args.domain, args.output, args.shodan_key)
    asyncio.run(engine.run_all())


if __name__ == "__main__":
    main()