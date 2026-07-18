import hashlib
from methods.base import BaseMethod


class Ripemd160Method(BaseMethod):
    name = "RIPEMD160"
    description = "RIPEMD160 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("ripemd160", text.encode()).hexdigest()
