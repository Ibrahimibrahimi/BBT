from methods.base import BaseMethod


class XOR22Method(BaseMethod):
    name = "XOR (0x22)"
    description = "XOR each byte with 0x22, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x22:02x}" for b in text.encode())
