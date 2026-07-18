import hashlib
from methods.base import BaseMethod


class Blake2bMethod(BaseMethod):
    name = "BLAKE2b"
    description = "BLAKE2b hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.blake2b(text.encode()).hexdigest()
