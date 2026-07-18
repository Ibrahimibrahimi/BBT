from methods.base import BaseMethod


class XOR01Method(BaseMethod):
    name = "XOR (0x01)"
    description = "XOR each byte with 0x01, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x01:02x}" for b in text.encode())
