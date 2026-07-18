from methods.base import BaseMethod


class CharCodesMethod(BaseMethod):
    name = "Char Codes"
    description = "U+ hex code points"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(f"U+{ord(c):04X}" for c in text)
