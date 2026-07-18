import base64
from methods.base import BaseMethod


class Base64PEMMethod(BaseMethod):
    name = "Base64 PEM"
    description = "Base64 with PEM-style line breaks"
    category = "Encoding"

    def encode(self, text: str) -> str:
        b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
        lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
        return "\n".join(lines)
