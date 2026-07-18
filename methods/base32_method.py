import base64
from methods.base import BaseMethod

class Base32Method(BaseMethod):
    name = "Base32"
    description = "Base32 encoding using RFC 4648 alphabet"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.b32encode(text.encode()).decode()
