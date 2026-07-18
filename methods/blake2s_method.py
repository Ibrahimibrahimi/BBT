import hashlib
from methods.base import BaseMethod


class Blake2sMethod(BaseMethod):
    name = "BLAKE2s"
    description = "BLAKE2s hash digest (hex)"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.blake2s(text.encode("utf-8")).hexdigest()
