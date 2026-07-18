import hashlib
from methods.base import BaseMethod


class Shake128Method(BaseMethod):
    name = "Shake128"
    description = "Shake128 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.shake_128(text.encode()).hexdigest(16)
