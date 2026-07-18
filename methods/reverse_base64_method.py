import base64
from methods.base import BaseMethod


class ReverseBase64Method(BaseMethod):
    name = "Reverse+Base64"
    description = "Reverses the string, then encodes the result in Base64"
    category = "Custom"

    def encode(self, text: str) -> str:
        reversed_text = text[::-1]
        return base64.b64encode(reversed_text.encode("utf-8")).decode("utf-8")
