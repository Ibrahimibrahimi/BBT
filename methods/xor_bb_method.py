from methods.base import BaseMethod


class XORBBMethod(BaseMethod):
    name = "XOR (0xBB)"
    description = "XOR each byte with 0xBB, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0xBB:02x}" for b in text.encode())
