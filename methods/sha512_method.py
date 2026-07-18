import hashlib
from methods.base import BaseMethod


class Sha512Method(BaseMethod):
    name = "SHA512"
    description = "SHA512 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha512(text.encode()).hexdigest()
