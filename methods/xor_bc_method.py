from methods.base import BaseMethod


class XORBCMethod(BaseMethod):
    name = "XOR (0xBC)"
    description = "XOR each byte with 0xBC, output as hex"
    category = "Cipher"

    def encode(self, text: str) -> str:
        return " ".join(f"{b ^ 0xBC:02x}" for b in text.encode())
