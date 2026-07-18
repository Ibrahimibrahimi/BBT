from methods.base import BaseMethod


class XOR33Method(BaseMethod):
    name = "XOR (0x33)"
    description = "XOR each byte with 0x33, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x33:02x}" for b in text.encode())
