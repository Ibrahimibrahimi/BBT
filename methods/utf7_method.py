import base64
from methods.base import BaseMethod


class UTF7Method(BaseMethod):
    name = "UTF-7"
    description = "UTF-7 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        result = []
        for char in text:
            if ord(char) < 128 and char not in "+-":
                result.append(char)
            else:
                b64 = base64.b64encode(char.encode("utf-16-be")).decode("ascii").rstrip("=")
                result.append("+" + b64 + "-")
        return "".join(result)
