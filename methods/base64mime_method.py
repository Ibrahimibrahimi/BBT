import base64
from methods.base import BaseMethod


class Base64MIMEMethod(BaseMethod):
    name = "Base64 MIME"
    description = "Base64 with MIME line wrapping"
    category = "Encoding"

    def encode(self, text: str) -> str:
        b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
        lines = [b64[i:i+76] for i in range(0, len(b64), 76)]
        return "\r\n".join(lines)
