from methods.base import BaseMethod


class XORF0Method(BaseMethod):
    name = "XOR (0xF0)"
    description = "XOR each byte with 0xF0, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0xF0:02x}" for b in text.encode())
