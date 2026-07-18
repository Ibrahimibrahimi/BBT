import hashlib
from methods.base import BaseMethod


class GOSTMethod(BaseMethod):
    name = "GOST"
    description = "GOST hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("md_gost", text.encode()).hexdigest()
