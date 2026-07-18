import hashlib
from methods.base import BaseMethod


class TigerMethod(BaseMethod):
    name = "Tiger"
    description = "Tiger hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("tiger", text.encode()).hexdigest()
