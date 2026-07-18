import hashlib
from methods.base import BaseMethod


class MD2Method(BaseMethod):
    name = "MD2"
    description = "MD2 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("md2", text.encode()).hexdigest()
