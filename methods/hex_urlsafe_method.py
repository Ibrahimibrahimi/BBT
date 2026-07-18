from methods.base import BaseMethod


class HexURLsafeMethod(BaseMethod):
    name = "Hex URL-safe"
    description = "URL-safe lowercase hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return "".join(f"{b:02x}" for b in text.encode("utf-8"))
