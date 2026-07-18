import hashlib
from methods.base import BaseMethod


class RIPEMD320Method(BaseMethod):
    name = "RIPEMD320"
    description = "RIPEMD-320 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("ripemd320", text.encode()).hexdigest()
