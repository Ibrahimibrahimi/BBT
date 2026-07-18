import hashlib
from methods.base import BaseMethod


class Sm3Method(BaseMethod):
    name = "SM3"
    description = "SM3 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("sm3", text.encode()).hexdigest()
