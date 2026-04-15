#!/usr/bin/env python3
"""
recon-arsenal :: template_runner.py
Runs YAML detection templates against targets.
Authorized use only.
"""

import argparse
import asyncio
import base64
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import aiohttp
import yaml
from colorama import Fore, Style, init
from rich.console import Console

init(autoreset=True)
console = Console()


@dataclass
class TemplateMatch:
    template_id: str
    name: str
    severity: str
    url: str
    matched_at: str
    evidence: str = ""


class TemplateRunner:
    def __init__(self, target: str, template_dir: str, threads: int, timeout: int,
                 output: Optional[str]):
        self.target = target.rstrip("/")
        self.template_dir = Path(template_dir)
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.matches: list[TemplateMatch] = []

    def _load_templates(self) -> list[dict]:
        templates = []
        for path in self.template_dir.glob("**/*.yaml"):
            try:
                text = path.read_text()
                for doc in yaml.safe_load_all(text):
                    if doc and "id" in doc:
                        templates.append(doc)
            except Exception as e:
                console.print(f"[dim red]Failed to load {path}: {e}[/dim red]")
        return templates

    def _interpolate(self, text: str) -> str:
        return text.replace("{{BaseURL}}", self.target)

    def _check_matchers(self, matchers: list, status: int,
                         body: str, headers: dict) -> bool:
        results = []
        for m in matchers:
            mtype = m.get("type","")
            condition = m.get("condition","or")
            part = m.get("part","body")

            if mtype == "status":
                results.append(status in m.get("status",[]))

            elif mtype == "word":
                src = headers.get(part, body) if part == "header" else body
                words = m.get("words",[])
                if condition == "and":
                    results.append(all(w.lower() in src.lower() for w in words))
                else:
                    results.append(any(w.lower() in src.lower() for w in words))

            elif mtype == "regex":
                src = body
                patterns = m.get("regex",[])
                results.append(any(re.search(p, src) for p in patterns))

        if not results:
            return False
        mc = matchers[0].get("matchers-condition","or") if matchers else "or"
        return all(results) if mc == "and" else any(results)

    async def _run_template(self, tpl: dict, session: aiohttp.ClientSession):
        tid = tpl.get("id","unknown")
        info = tpl.get("info",{})
        name = info.get("name", tid)
        severity = info.get("severity","info").upper()

        for req in tpl.get("requests", []):
            method = req.get("method","GET").upper()
            paths = req.get("path", [])
            body = req.get("body","")
            hdrs = req.get("headers",{})
            matchers = req.get("matchers",[])
            mc = req.get("matchers-condition","or")

            for path in paths:
                url = self._interpolate(path)
                try:
                    async with session.request(
                        method, url,
                        headers=hdrs,
                        data=body or None,
                        ssl=False,
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as r:
                        resp_body = await r.text(errors="ignore")
                        resp_hdrs = {k+": "+v for k,v in r.headers.items()}
                        resp_hdrs_str = "\n".join(resp_hdrs)

                        if self._check_matchers(matchers, r.status, resp_body, {"header": resp_hdrs_str}):
                            match = TemplateMatch(
                                template_id=tid,
                                name=name,
                                severity=severity,
                                url=url,
                                matched_at=url,
                                evidence=resp_body[:300],
                            )
                            self.matches.append(match)
                            color = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green"}.get(severity,"blue")
                            console.print(f"  [{color}][{severity}][/{color}] {name} — {url}")
                except Exception:
                    pass

    async def run(self):
        templates = self._load_templates()
        console.print(f"[bold]Target:[/bold] {self.target} | "
                      f"[bold]Templates:[/bold] {len(templates)}")

        connector = aiohttp.TCPConnector(limit=self.threads, ssl=False)
        sem = asyncio.Semaphore(self.threads)

        async def limited(tpl):
            async with sem:
                await self._run_template(tpl, session)

        async with aiohttp.ClientSession(connector=connector) as session:
            await asyncio.gather(*[limited(t) for t in templates])

        console.print(f"\n[bold]Done.[/bold] Matches: {len(self.matches)}")
        if self.output:
            Path(self.output).write_text(
                json.dumps([m.__dict__ for m in self.matches], indent=2)
            )
            console.print(f"[green]Saved → {self.output}[/green]")


def main():
    p = argparse.ArgumentParser(description="Template runner — authorized use only")
    p.add_argument("-u","--url", required=True, help="Target base URL")
    p.add_argument("-t","--templates", default=".", help="Template directory")
    p.add_argument("--threads", type=int, default=20)
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("-o","--output", help="JSON output")
    args = p.parse_args()

    asyncio.run(TemplateRunner(
        args.url, args.templates, args.threads, args.timeout, args.output
    ).run())


if __name__ == "__main__":
    main()