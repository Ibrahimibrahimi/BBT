import hashlib
from methods.base import BaseMethod


class SHA3_256Method(BaseMethod):
    name = "SHA3-256"
    description = "SHA3-256 hash digest (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha3_256(text.encode("utf-8")).hexdigest()
