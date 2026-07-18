from methods.base import BaseMethod


class XOR66Method(BaseMethod):
    name = "XOR (0x66)"
    description = "XOR each byte with 0x66, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x66:02x}" for b in text.encode())
