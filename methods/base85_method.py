import base64
from methods.base import BaseMethod

class Base85Method(BaseMethod):
    name = "Base85"
    description = "Base85 encoding (Ascii85 variant)"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.b85encode(text.encode()).decode()
