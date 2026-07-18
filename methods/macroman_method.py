from methods.base import BaseMethod


class MacRomanMethod(BaseMethod):
    name = "Mac Roman"
    description = "Mac Roman hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode("mac_roman")
        return " ".join(f"{b:02x}" for b in data)
