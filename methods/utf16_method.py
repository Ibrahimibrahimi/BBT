from methods.base import BaseMethod


class UTF16Method(BaseMethod):
    name = "UTF-16"
    description = "UTF-16LE hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        encoded = text.encode("utf-16-le")
        return " ".join(f"{encoded[i]:02x}{encoded[i+1]:02x}" for i in range(0, len(encoded), 2))
