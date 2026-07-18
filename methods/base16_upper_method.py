import base64
from methods.base import BaseMethod

class Base16UpperMethod(BaseMethod):
    name = "Base16 Upper"
    description = "Base16 encoding with uppercase hexadecimal digits"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.b16encode(text.encode()).decode()
