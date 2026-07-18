from methods.base import BaseMethod


class Checksum8Method(BaseMethod):
    name = "Checksum8"
    description = "Checksum8, simple 8-bit sum mod 256"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        total = sum(data) % 256
        return f"{total:02x}"
