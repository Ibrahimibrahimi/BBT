from methods.base import BaseMethod


class XOR0AMethod(BaseMethod):
    name = "XOR (0x0A)"
    description = "XOR each byte with 0x0A, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x0A:02x}" for b in text.encode())
