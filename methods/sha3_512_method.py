import hashlib
from methods.base import BaseMethod


class Sha3512Method(BaseMethod):
    name = "SHA3-512"
    description = "SHA3-512 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha3_512(text.encode()).hexdigest()
