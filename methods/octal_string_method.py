from methods.base import BaseMethod

class OctalStringMethod(BaseMethod):
    name = "Octal"
    description = "Octal representation of each byte"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return ' '.join(oct(b) for b in text.encode())
