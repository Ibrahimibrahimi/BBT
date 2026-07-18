import hashlib
from methods.base import BaseMethod


class Md4Method(BaseMethod):
    name = "MD4"
    description = "MD4 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("md4", text.encode()).hexdigest()
