import hashlib
from methods.base import BaseMethod


class RIPEMD256Method(BaseMethod):
    name = "RIPEMD256"
    description = "RIPEMD-256 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("ripemd256", text.encode()).hexdigest()
