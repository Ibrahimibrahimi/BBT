from methods.base import BaseMethod


class HexSpacesMethod(BaseMethod):
    name = "Hex (spaced)"
    description = "Hex with spaces between bytes"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(f"{b:02x}" for b in text.encode("utf-8"))
