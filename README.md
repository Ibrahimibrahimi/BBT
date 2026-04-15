# recon-arsenal ??

> A curated, production-grade collection of tools, scripts, and automation
> workflows purpose-built for offensive security researchers and bug bounty hunters.

This repository consolidates the full attack surface enumeration lifecycle —
from passive reconnaissance to active exploitation — into a single, structured arsenal.

## Coverage

- **Subdomain & DNS enumeration** — amass, subfinder, dnsx pipelines
- **HTTP probing & fingerprinting** — httpx, whatweb, technology detection
- **Path & parameter fuzzing** — ffuf, feroxbuster, arjun
- **SSRF, LFI, SQLi, XSS detection** — nuclei templates + custom scripts
- **JS endpoint & secret extraction** — linkfinder, secretfinder, trufflehog
- **Cloud & infrastructure exposure** — S3, GCP, Azure misconfig checks
- **OSINT & passive intel gathering** — shodan, dorking, WHOIS correlation
- **Reporting & output formatting** — parsers, markdown exporters

## Philosophy

Every tool here is selected for real-world effectiveness, not popularity.
Scripts are modular, pipeline-friendly, and designed to chain together —
output of one feeds directly into the next.

## Structure