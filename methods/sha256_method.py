import hashlib
from methods.base import BaseMethod


class SHA256Method(BaseMethod):
    name = "SHA256"
    description = "SHA-256 hash digest (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
