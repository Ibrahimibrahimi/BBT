from methods.base import BaseMethod


class XOR55Method(BaseMethod):
    name = "XOR (0x55)"
    description = "XOR each byte with 0x55, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x55:02x}" for b in text.encode())
