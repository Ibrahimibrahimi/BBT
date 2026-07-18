from methods.base import BaseMethod


class ASCIIValuesMethod(BaseMethod):
    name = "ASCII Values"
    description = "Decimal ASCII values, space-separated"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(str(ord(c)) for c in text)
