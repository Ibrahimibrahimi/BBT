from methods.base import BaseMethod

class BinaryStringMethod(BaseMethod):
    name = "Binary String"
    description = "Binary representation (8-bit per byte)"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return ' '.join(format(b, '08b') for b in text.encode())
