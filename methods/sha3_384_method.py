import hashlib
from methods.base import BaseMethod


class Sha3384Method(BaseMethod):
    name = "SHA3-384"
    description = "SHA3-384 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.sha3_384(text.encode()).hexdigest()
