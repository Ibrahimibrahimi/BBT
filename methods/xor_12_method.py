from methods.base import BaseMethod


class XOR12Method(BaseMethod):
    name = "XOR (0x12)"
    description = "XOR each byte with 0x12, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x12:02x}" for b in text.encode())
