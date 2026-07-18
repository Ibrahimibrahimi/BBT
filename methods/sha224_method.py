import hashlib
from methods.base import BaseMethod


class Sha224Method(BaseMethod):
    name = "SHA224"
    description = "SHA224 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha224(text.encode()).hexdigest()
