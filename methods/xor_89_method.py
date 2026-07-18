from methods.base import BaseMethod


class XOR89Method(BaseMethod):
    name = "XOR (0x89)"
    description = "XOR each byte with 0x89, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x89:02x}" for b in text.encode())
