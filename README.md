# Crypter

An interactive CLI that takes a string and prints it encoded/encrypted/hashed
using every method it can find — with colors, tables, and a friendly Rich UI.

Methods are **plugins**: drop a new file in `methods/`, and it's picked up
automatically. No editing `main.py`, no registration step.

## Project structure

```
crypter/
├── main.py              # CLI entrypoint (interactive + one-shot modes)
├── loader.py             # Scans methods/ and auto-loads every method
├── methods/
│   ├── base.py            # BaseMethod — the interface every method implements
│   ├── base64_method.py   # example: Base64 encoding
│   ├── hex_method.py      # example: Hex encoding
│   ├── rot13_method.py    # example: ROT13 cipher
│   ├── md5_method.py      # example: MD5 hash
│   └── sha256_method.py   # example: SHA256 hash
├── requirements.txt
└── README.md
```

Currently ships with **5 methods** as a starter set (2 encodings, 1 cipher,
2 hashes). The architecture supports 20+ — just add more files the same way.

## Install

```bash
pip install -r requirements.txt
```

## Usage

**Interactive mode** (recommended — type a string, get a table, repeat):
```bash
python3 main.py
```

**One-shot mode** (positional arg or `--target`, both work the same):
```bash
python3 main.py "Hello World"
python3 main.py --target "hi this is a text"
```

**Check for a match** — test whether a value (e.g. a partial/leaked hash)
appears as a case-insensitive substring in any of the results. Matching rows
are highlighted in the table and summarized below it:
```bash
python3 main.py --target "hi this is a text" --check-match "ef93836"
```
Exits with code `0` if a match was found, `1` if not — handy for scripting
(`&&` / `||` chains, CI checks, etc.).

**List all loaded methods:**
```bash
python3 main.py --list
```

Interactive-mode commands:
- `:list` — show all loaded methods
- `:help` — show help
- `:q` — quit

## Adding a new method

Create a new file in `methods/`, e.g. `methods/caesar_method.py`:

```python
from methods.base import BaseMethod

class CaesarMethod(BaseMethod):
    name = "Caesar (+3)"
    description = "Classic Caesar cipher, shift of 3"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 3) % 26 + base)
            else:
                result += ch
        return result
```

That's it — no other file needs to change. Run `python3 main.py --list` and
your new method will already be there.

### Rules for a valid method file

- Must define a class that inherits from `methods.base.BaseMethod`.
- Must implement `encode(self, text: str) -> str`.
- Should set `name`, `description`, and `category` class attributes.
- `category` controls the color grouping in the table (`Encoding` = cyan,
  `Hash` = magenta, `Cipher` = yellow; anything else defaults to green).

If a method file fails to import, or a method raises an exception when run,
`crypter` will not crash — it skips/flags it and keeps going.

## Ideas for methods to add (to reach 20+)

Encodings: Base32, Base85, URL encoding, Binary, Morse code, UUencode
Hashes: SHA1, SHA512, CRC32, Blake2b, SHA3-256
Ciphers: Caesar, Vigenère, Atbash, XOR (fixed key), Rail Fence
Other: ASCII art, Reverse string, Leetspeak, NATO phonetic, Base58
