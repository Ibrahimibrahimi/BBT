from methods.base import BaseMethod


class XOR42Method(BaseMethod):
    name = "XOR (0x42)"
    description = "XOR each byte with 0x42, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x42:02x}" for b in text.encode())
