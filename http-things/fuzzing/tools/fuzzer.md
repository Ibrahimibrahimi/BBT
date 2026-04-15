# fuzzer

Async HTTP fuzzer with auto-calibration, extension expansion, proxy support, and rich output.

## Usage

```bash
pip install -r requirements.txt

# Directory fuzzing
python fuzzer.py -u https://target.com/FUZZ -w ../wordlists/common.txt

# With extensions & filter 404
python fuzzer.py -u https://target.com/FUZZ -w ../wordlists/common.txt -e php,html,js -fc 404

# POST fuzzing
python fuzzer.py -u https://target.com/login -X POST -D "user=admin&pass=FUZZ" -w ../wordlists/passwords.txt

# With proxy (Burp Suite)
python fuzzer.py -u https://target.com/FUZZ -w ../wordlists/common.txt -p http://127.0.0.1:8080

# Save JSON output
python fuzzer.py -u https://target.com/FUZZ -w ../wordlists/common.txt -o results.json -of json
```

## Features
- Async engine (aiohttp) — up to 500 req/s
- Auto-calibration: detects & filters baseline 404 body sizes
- FUZZ placeholder anywhere in URL, headers, or POST body
- Extension explosion (-e php,asp,html)
- Filter by status code, size, word count, regex
- Follow redirects, custom headers/cookies
- Random User-Agent rotation
- JSON / TXT output