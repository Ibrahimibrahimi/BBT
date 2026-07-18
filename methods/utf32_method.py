from methods.base import BaseMethod


class UTF32Method(BaseMethod):
    name = "UTF-32"
    description = "UTF-32LE hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        encoded = text.encode("utf-32-le")
        return " ".join(
            f"{encoded[i]:02x}{encoded[i+1]:02x}{encoded[i+2]:02x}{encoded[i+3]:02x}"
            for i in range(0, len(encoded), 4)
        )
