import hashlib
from methods.base import BaseMethod


class Sha512224Method(BaseMethod):
    name = "SHA512/224"
    description = "SHA512/224 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("sha512_224", text.encode()).hexdigest()
