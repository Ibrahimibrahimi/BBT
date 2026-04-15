#!/usr/bin/env python3
"""
recon-arsenal :: recon.py
Active recon: subdomain brute-force, port scanning, HTTP probing,
technology fingerprinting, WAF detection.
Authorized use only.
"""

import argparse
import asyncio
import json
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiohttp
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.GREEN}
+--------------------------------------------------+
¦         recon-arsenal :: recon v1.0              ¦
¦  Active Reconnaissance — Authorized Use Only     ¦
+--------------------------------------------------+
{Style.RESET_ALL}"""

COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,465,587,
                993,995,3306,3389,5432,5900,6379,8080,8443,
                8888,9200,9300,27017,27018]

WAF_SIGNATURES = {
    "Cloudflare":    ["cf-ray", "cloudflare"],
    "AWS WAF":       ["x-amzn-requestid", "awselb"],
    "Akamai":        ["akamai-ghost", "x-check-cacheable"],
    "Imperva":       ["x-iinfo", "visid_incap"],
    "Sucuri":        ["x-sucuri-id", "sucuri"],
    "F5 BIG-IP":     ["bigipserver", "x-cnection"],
    "Barracuda":     ["barra_counter_session", "barracudawaf"],
    "Fortinet":      ["fortigate", "cookiesession1"],
    "ModSecurity":   ["mod_security", "NOYB"],
}


@dataclass
class SubdomainResult:
    subdomain: str
    ip: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    waf: str = ""
    redirect: str = ""
    alive: bool = False


@dataclass
class PortResult:
    host: str
    port: int
    open: bool
    banner: str = ""


class ReconEngine:
    def __init__(self, domain: str, wordlist: Optional[str],
                 ports: list[int], threads: int, output: Optional[str],
                 timeout: int):
        self.domain = domain.lower().lstrip("www.")
        self.wordlist = wordlist
        self.ports = ports or COMMON_PORTS
        self.threads = threads
        self.output = output
        self.timeout = timeout
        self.subdomain_results: list[SubdomainResult] = []
        self.port_results: list[PortResult] = []
        self._semaphore: asyncio.Semaphore = None

    def _load_wordlist(self) -> list[str]:
        path = Path(self.wordlist) if self.wordlist else \
               Path(__file__).parent.parent / "wordlists" / "subdomains.txt"
        if not path.exists():
            console.print(f"[yellow]Wordlist not found: {path}. Using built-in list.[/yellow]")
            return BUILTIN_SUBDOMAINS
        return [l.strip() for l in path.read_text(errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")]

    async def _probe_subdomain(self, sub: str, session: aiohttp.ClientSession,
                                progress=None, task=None) -> Optional[SubdomainResult]:
        fqdn = f"{sub}.{self.domain}"
        result = SubdomainResult(subdomain=fqdn)
        try:
            ip = socket.gethostbyname(fqdn)
            result.ip = ip
        except Exception:
            if progress and task is not None:
                progress.advance(task)
            return None  # DNS NXDOMAIN

        # HTTP probe
        for scheme in ("https", "http"):
            try:
                async with self._semaphore:
                    url = f"{scheme}://{fqdn}"
                    async with session.get(
                        url, ssl=False, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as r:
                        body = await r.text(errors="ignore")
                        result.status = r.status
                        result.alive = True
                        result.redirect = str(r.url) if str(r.url) != url else ""
                        result.server = r.headers.get("server","")

                        # Title
                        import re
                        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                        result.title = (m.group(1)[:60].strip() if m else "")

                        # WAF
                        hdrs = " ".join(f"{k}:{v}" for k,v in r.headers.items()).lower()
                        for waf, sigs in WAF_SIGNATURES.items():
                            if any(s in hdrs for s in sigs):
                                result.waf = waf
                                break
                        break
            except Exception:
                continue

        if progress and task is not None:
            progress.advance(task)
        return result if result.alive else result  # return all (even dead DNS-resolved)

    async def enumerate_subdomains(self, session: aiohttp.ClientSession):
        console.print(f"\n[bold green][ Subdomain Enumeration ][/bold green]")
        words = self._load_wordlist()
        console.print(f"  Probing [bold]{len(words)}[/bold] subdomains…")

        with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      console=console) as progress:
            task = progress.add_task("Enumerating…", total=len(words))
            results = await asyncio.gather(*[
                self._probe_subdomain(w, session, progress, task) for w in words
            ])

        self.subdomain_results = [r for r in results if r]
        alive = [r for r in self.subdomain_results if r.alive]

        t = Table(title=f"Live Subdomains ({len(alive)})", show_lines=False)
        t.add_column("Subdomain", style="green")
        t.add_column("IP"); t.add_column("Status"); t.add_column("WAF"); t.add_column("Title")
        for r in sorted(alive, key=lambda x: x.subdomain):
            t.add_row(r.subdomain, r.ip, str(r.status), r.waf or "—", r.title or "—")
        console.print(t)

    async def _scan_port(self, host: str, port: int) -> PortResult:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            banner = ""
            try:
                writer.write(b"\r\n")
                data = await asyncio.wait_for(reader.read(256), timeout=2)
                banner = data.decode(errors="ignore").strip()[:80]
            except Exception:
                pass
            writer.close()
            return PortResult(host=host, port=port, open=True, banner=banner)
        except Exception:
            return PortResult(host=host, port=port, open=False)

    async def scan_ports(self):
        console.print(f"\n[bold green][ Port Scan ][/bold green]")
        try:
            ip = socket.gethostbyname(self.domain)
        except Exception:
            console.print(f"  [red]Cannot resolve {self.domain}[/red]")
            return

        console.print(f"  Scanning {len(self.ports)} ports on {ip}…")
        sem = asyncio.Semaphore(200)

        async def limited_scan(p):
            async with sem:
                return await self._scan_port(ip, p)

        results = await asyncio.gather(*[limited_scan(p) for p in self.ports])
        self.port_results = results

        open_ports = [r for r in results if r.open]
        if open_ports:
            t = Table(title=f"Open Ports on {ip}")
            t.add_column("Port", style="green"); t.add_column("Banner")
            for r in open_ports:
                t.add_row(str(r.port), r.banner or "—")
            console.print(t)
        else:
            console.print("  [dim]No open ports found.[/dim]")

    def save(self):
        if not self.output:
            return
        data = {
            "domain": self.domain,
            "subdomains": [r.__dict__ for r in self.subdomain_results],
            "ports": [r.__dict__ for r in self.port_results if r.open],
        }
        Path(self.output).write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]Saved ? {self.output}[/green]")

    async def run(self, do_ports: bool = True):
        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        self._semaphore = asyncio.Semaphore(self.threads)
        async with aiohttp.ClientSession(connector=connector) as session:
            await self.enumerate_subdomains(session)
        if do_ports:
            await self.scan_ports()
        self.save()


BUILTIN_SUBDOMAINS = [
    "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
    "vpn","m","shop","ftp","mail2","test","portal","api","dev","staging","app",
    "admin","host","beta","direct","login","support","cdn","news","web","upload",
    "static","media","img","assets","video","forum","help","dashboard","intranet",
    "internal","aws","gcp","k8s","jenkins","gitlab","jira","confluence","docs",
]


def main():
    print(BANNER)
    p = argparse.ArgumentParser(description="Recon engine — authorized testing only")
    p.add_argument("domain", help="Target domain")
    p.add_argument("-w", "--wordlist", help="Subdomain wordlist")
    p.add_argument("--ports", help="Comma-separated ports (default: common 25)")
    p.add_argument("-t", "--threads", type=int, default=100)
    p.add_argument("--timeout", type=int, default=6)
    p.add_argument("--no-ports", action="store_true", help="Skip port scan")
    p.add_argument("-o", "--output", help="JSON output file")
    args = p.parse_args()

    ports = [int(x) for x in args.ports.split(",")] if args.ports else COMMON_PORTS
    engine = ReconEngine(args.domain, args.wordlist, ports, args.threads, args.output, args.timeout)
    asyncio.run(engine.run(do_ports=not args.no_ports))


if __name__ == "__main__":
    main()