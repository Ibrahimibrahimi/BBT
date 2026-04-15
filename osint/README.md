# osint

OSINT automation: WHOIS/RDAP, DNS records, certificate transparency, subdomain discovery, email harvesting, technology fingerprinting, Google dork generation, IP geolocation.

## Usage

```bash
pip install -r requirements.txt

python osint.py example.com
python osint.py example.com -o report.json
```

## Output

JSON report covering: WHOIS data, full DNS records, subdomains (crt.sh + HackerTarget), emails, technologies, IP geolocation, and ready-to-use Google dorks.