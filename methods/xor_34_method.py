from methods.base import BaseMethod


class XOR34Method(BaseMethod):
    name = "XOR (0x34)"
    description = "XOR each byte with 0x34, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x34:02x}" for b in text.encode())
