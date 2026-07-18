import hashlib
from methods.base import BaseMethod


class RIPEMD128Method(BaseMethod):
    name = "RIPEMD128"
    description = "RIPEMD-128 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("ripemd128", text.encode()).hexdigest()
