import base64
from methods.base import BaseMethod


class Base64Method(BaseMethod):
    name = "Base64"
    description = "Standard Base64 encoding (RFC 4648)"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")
