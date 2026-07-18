import hashlib
from methods.base import BaseMethod


class Sha512256Method(BaseMethod):
    name = "SHA512/256"
    description = "SHA512/256 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("sha512_256", text.encode()).hexdigest()
