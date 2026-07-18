from methods.base import BaseMethod


class XOR11Method(BaseMethod):
    name = "XOR (0x11)"
    description = "XOR each byte with 0x11, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0x11:02x}" for b in text.encode())
