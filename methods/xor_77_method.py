from methods.base import BaseMethod


class XOR77Method(BaseMethod):
    name = "XOR (0x77)"
    description = "XOR each byte with 0x77, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x77:02x}" for b in text.encode())
