#!/usr/bin/env python3
"""
recon-arsenal :: fuzzer.py
Powerful HTTP fuzzer for authorized security testing.
"""

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

import aiohttp
from colorama import Fore, Style, init
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.CYAN}
+-----------------------------------------------+
¦          recon-arsenal :: fuzzer v1.0         ¦
¦   Authorized Security Testing Only — FUZZ     ¦
+-----------------------------------------------+
{Style.RESET_ALL}"""

# ----------------------------------------------
# Data structures
# ----------------------------------------------

@dataclass
class FuzzResult:
    url: str
    method: str
    status: int
    length: int
    words: int
    lines: int
    elapsed: float
    redirect: Optional[str] = None
    payload: str = ""
    headers: dict = field(default_factory=dict)


@dataclass
class FuzzConfig:
    url: str
    wordlist: str
    method: str = "GET"
    threads: int = 50
    timeout: int = 10
    delay: float = 0.0
    proxy: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    post_data: Optional[str] = None
    filter_codes: list = field(default_factory=list)
    match_codes: list = field(default_factory=list)
    filter_size: list = field(default_factory=list)
    filter_words: list = field(default_factory=list)
    filter_regex: Optional[str] = None
    follow_redirects: bool = False
    recursion: bool = False
    recursion_depth: int = 2
    extensions: list = field(default_factory=list)
    user_agent: Optional[str] = None
    random_agent: bool = False
    output: Optional[str] = None
    output_format: str = "txt"
    verbose: bool = False
    rate_limit: int = 0          # requests/second, 0 = unlimited
    auto_calibrate: bool = True  # auto-detect baseline and filter noise


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


# ----------------------------------------------
# Core fuzzer engine
# ----------------------------------------------

class Fuzzer:
    def __init__(self, config: FuzzConfig):
        self.config = config
        self.results: list[FuzzResult] = []
        self.errors: int = 0
        self.requests_done: int = 0
        self.baseline_sizes: set[int] = set()
        self._semaphore: asyncio.Semaphore = None
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._filter_re = re.compile(config.filter_regex) if config.filter_regex else None
        self._session: aiohttp.ClientSession = None

    def load_wordlist(self) -> list[str]:
        path = Path(self.config.wordlist)
        if not path.exists():
            console.print(f"[red]Wordlist not found: {path}[/red]")
            sys.exit(1)
        words = path.read_text(errors="ignore").splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
        # Expand with extensions
        if self.config.extensions:
            expanded = []
            for w in words:
                expanded.append(w)
                for ext in self.config.extensions:
                    expanded.append(f"{w}.{ext.lstrip('.')}")
            return expanded
        return words

    def _pick_ua(self) -> str:
        if self.config.random_agent:
            return random.choice(USER_AGENTS)
        return self.config.user_agent or USER_AGENTS[0]

    def _build_headers(self) -> dict:
        h = {"User-Agent": self._pick_ua()}
        h.update(self.config.headers)
        return h

    def _inject_payload(self, payload: str) -> tuple[str, Optional[str]]:
        """Return (url, body) with FUZZ replaced by payload."""
        marker = "FUZZ"
        url = self.config.url.replace(marker, payload) if marker in self.config.url else \
              urljoin(self.config.url.rstrip("/") + "/", payload)
        body = None
        if self.config.post_data:
            body = self.config.post_data.replace(marker, payload)
        return url, body

    def _should_filter(self, r: FuzzResult) -> bool:
        cfg = self.config
        if cfg.match_codes and r.status not in cfg.match_codes:
            return True
        if cfg.filter_codes and r.status in cfg.filter_codes:
            return True
        if cfg.filter_size and r.length in cfg.filter_size:
            return True
        if cfg.filter_words and r.words in cfg.filter_words:
            return True
        if self._filter_re and self._filter_re.search(str(r.length)):
            return True
        if self.config.auto_calibrate and r.length in self.baseline_sizes:
            return True
        return False

    async def _calibrate(self):
        """Fetch a few random paths to detect baseline 404 sizes."""
        console.print("[dim]Calibrating baseline...[/dim]")
        probes = ["__recon_probe_xyz__", "recon_arsenal_test_000", "probe_aaabbbccc"]
        for probe in probes:
            url, body = self._inject_payload(probe)
            try:
                async with self._session.request(
                    self.config.method, url,
                    headers=self._build_headers(),
                    data=body,
                    allow_redirects=self.config.follow_redirects,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                ) as resp:
                    content = await resp.read()
                    self.baseline_sizes.add(len(content))
            except Exception:
                pass
        console.print(f"[dim]Baseline sizes (auto-filtered): {self.baseline_sizes}[/dim]")

    async def _fuzz_one(self, payload: str, progress=None, task=None) -> Optional[FuzzResult]:
        cfg = self.config
        url, body = self._inject_payload(payload)
        headers = self._build_headers()
        start = time.monotonic()
        try:
            async with self._semaphore:
                if cfg.delay > 0:
                    await asyncio.sleep(cfg.delay)
                async with self._session.request(
                    cfg.method, url,
                    headers=headers,
                    data=body,
                    cookies=cfg.cookies,
                    allow_redirects=cfg.follow_redirects,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=cfg.timeout),
                ) as resp:
                    elapsed = time.monotonic() - start
                    content = await resp.text(errors="ignore")
                    redirect = str(resp.url) if resp.history else None
                    result = FuzzResult(
                        url=url,
                        method=cfg.method,
                        status=resp.status,
                        length=len(content),
                        words=len(content.split()),
                        lines=content.count("\n"),
                        elapsed=round(elapsed, 3),
                        redirect=redirect,
                        payload=payload,
                        headers=dict(resp.headers),
                    )
                    return result
        except asyncio.TimeoutError:
            self.errors += 1
        except Exception as e:
            self.errors += 1
            if cfg.verbose:
                console.print(f"[dim red]ERR {payload}: {e}[/dim red]")
        finally:
            self.requests_done += 1
            if progress and task is not None:
                progress.advance(task)
        return None

    def _format_status(self, code: int) -> str:
        if 200 <= code < 300:
            return f"[green]{code}[/green]"
        if 300 <= code < 400:
            return f"[cyan]{code}[/cyan]"
        if 400 <= code < 500:
            return f"[yellow]{code}[/yellow]"
        return f"[red]{code}[/red]"

    def _print_result(self, r: FuzzResult):
        redir = f" ? {r.redirect}" if r.redirect else ""
        console.print(
            f"[bold]{r.payload:<40}[/bold] "
            f"{self._format_status(r.status)} "
            f"[dim]L:{r.lines} W:{r.words} C:{r.length}[/dim] "
            f"[dim]{r.elapsed}s{redir}[/dim]"
        )

    def _save_results(self):
        if not self.config.output:
            return
        path = Path(self.config.output)
        if self.config.output_format == "json":
            data = [
                {k: v for k, v in r.__dict__.items() if k != "headers"}
                for r in self.results
            ]
            path.write_text(json.dumps(data, indent=2))
        else:
            lines = [
                f"{r.status} {r.length:>8}B {r.words:>6}W {r.elapsed:>6}s  {r.url}"
                for r in self.results
            ]
            path.write_text("\n".join(lines))
        console.print(f"\n[green]Results saved ? {path}[/green]")

    async def run(self):
        words = self.load_wordlist()
        console.print(f"[bold]Wordlist:[/bold] {len(words)} entries | "
                      f"[bold]Threads:[/bold] {self.config.threads} | "
                      f"[bold]Method:[/bold] {self.config.method}")

        connector = aiohttp.TCPConnector(limit=self.config.threads, ssl=False)
        proxy = self.config.proxy

        async with aiohttp.ClientSession(connector=connector) as session:
            self._session = session
            self._semaphore = asyncio.Semaphore(self.config.threads)

            if self.config.auto_calibrate:
                await self._calibrate()

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Fuzzing…", total=len(words))

                async def worker(payload):
                    r = await self._fuzz_one(payload, progress, task)
                    if r and not self._should_filter(r):
                        self.results.append(r)
                        self._print_result(r)

                await asyncio.gather(*[worker(w) for w in words])

        console.print(f"\n[bold green]Done.[/bold green] "
                      f"Hits: {len(self.results)} | "
                      f"Errors: {self.errors} | "
                      f"Total: {self.requests_done}")
        self._save_results()


# ----------------------------------------------
# CLI
# ----------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="recon-arsenal fuzzer — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-u", "--url", required=True,
                   help="Target URL. Use FUZZ as placeholder. e.g. https://target.com/FUZZ")
    p.add_argument("-w", "--wordlist", required=True, help="Path to wordlist")
    p.add_argument("-X", "--method", default="GET",
                   choices=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
    p.add_argument("-t", "--threads", type=int, default=50)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="Delay between requests (per thread) in seconds")
    p.add_argument("-p", "--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="Name:Value", help="Custom header (repeatable)")
    p.add_argument("-b", "--cookie", action="append", default=[],
                   metavar="name=value")
    p.add_argument("-D", "--data", help="POST body (use FUZZ as placeholder)")
    p.add_argument("-fc", "--filter-code", action="append", type=int, default=[],
                   metavar="CODE", help="Filter response codes (repeatable)")
    p.add_argument("-mc", "--match-code", action="append", type=int, default=[],
                   metavar="CODE", help="Match only these codes (repeatable)")
    p.add_argument("-fs", "--filter-size", action="append", type=int, default=[])
    p.add_argument("-fw", "--filter-words", action="append", type=int, default=[])
    p.add_argument("-fr", "--filter-regex", help="Filter by regex on response body")
    p.add_argument("-e", "--extensions", help="Comma-separated extensions: php,html,js")
    p.add_argument("-r", "--follow-redirects", action="store_true")
    p.add_argument("--no-calibrate", action="store_true",
                   help="Disable auto-calibration of baseline sizes")
    p.add_argument("-ra", "--random-agent", action="store_true")
    p.add_argument("-o", "--output", help="Output file path")
    p.add_argument("-of", "--output-format", choices=["txt", "json"], default="txt")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    cookies = {}
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    extensions = [e.strip() for e in args.extensions.split(",")] if args.extensions else []

    cfg = FuzzConfig(
        url=args.url,
        wordlist=args.wordlist,
        method=args.method,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        post_data=args.data,
        filter_codes=args.filter_code,
        match_codes=args.match_code,
        filter_size=args.filter_size,
        filter_words=args.filter_words,
        filter_regex=args.filter_regex,
        follow_redirects=args.follow_redirects,
        extensions=extensions,
        random_agent=args.random_agent,
        output=args.output,
        output_format=args.output_format,
        verbose=args.verbose,
        auto_calibrate=not args.no_calibrate,
    )

    fuzzer = Fuzzer(cfg)
    asyncio.run(fuzzer.run())


if __name__ == "__main__":
    main()