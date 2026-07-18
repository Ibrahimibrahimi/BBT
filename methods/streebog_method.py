import hashlib
from methods.base import BaseMethod


class StreebogMethod(BaseMethod):
    name = "Streebog"
    description = "Streebog-256 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        return hashlib.new("streebog_256", text.encode()).hexdigest()
