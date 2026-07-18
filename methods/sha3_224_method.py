import hashlib
from methods.base import BaseMethod


class Sha3224Method(BaseMethod):
    name = "SHA3-224"
    description = "SHA3-224 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha3_224(text.encode()).hexdigest()
