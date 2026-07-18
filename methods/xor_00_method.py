from methods.base import BaseMethod


class XOR00Method(BaseMethod):
    name = "XOR (0x00)"
    description = "XOR each byte with 0x00, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x00:02x}" for b in text.encode())
