from methods.base import BaseMethod


class XOR44Method(BaseMethod):
    name = "XOR (0x44)"
    description = "XOR each byte with 0x44, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x44:02x}" for b in text.encode())
