import hashlib
from methods.base import BaseMethod


class SHA512_384Method(BaseMethod):
    name = "SHA512/384"
    description = "SHA-512/384 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("sha512_384", text.encode()).hexdigest()
