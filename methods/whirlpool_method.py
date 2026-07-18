import hashlib
from methods.base import BaseMethod


class WhirlpoolMethod(BaseMethod):
    name = "Whirlpool"
    description = "Whirlpool hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("whirlpool", text.encode()).hexdigest()
