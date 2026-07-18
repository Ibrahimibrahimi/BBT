from methods.base import BaseMethod


class HexMethod(BaseMethod):
    name = "Hex"
    description = "Hexadecimal representation of UTF-8 bytes"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return text.encode("utf-8").hex()
