from methods.base import BaseMethod


class XORDEMethod(BaseMethod):
    name = "XOR (0xDE)"
    description = "XOR each byte with 0xDE, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0xDE:02x}" for b in text.encode())
