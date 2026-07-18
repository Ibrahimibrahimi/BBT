import base64
from methods.base import BaseMethod

class Ascii85Method(BaseMethod):
    name = "Ascii85"
    description = "Ascii85 (Base85) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.a85encode(text.encode()).decode()
