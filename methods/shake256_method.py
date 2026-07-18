import hashlib
from methods.base import BaseMethod


class Shake256Method(BaseMethod):
    name = "Shake256"
    description = "Shake256 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.shake_256(text.encode()).hexdigest(16)
