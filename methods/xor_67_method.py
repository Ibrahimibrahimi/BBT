from methods.base import BaseMethod


class XOR67Method(BaseMethod):
    name = "XOR (0x67)"
    description = "XOR each byte with 0x67, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x67:02x}" for b in text.encode())
