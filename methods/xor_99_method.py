from methods.base import BaseMethod


class XOR99Method(BaseMethod):
    name = "XOR (0x99)"
    description = "XOR each byte with 0x99, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x99:02x}" for b in text.encode())
