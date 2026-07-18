from methods.base import BaseMethod

class BinToDecMethod(BaseMethod):
    name = "Binary to Decimal"
    description = "Parse as binary, output decimal"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return str(int(text.strip(), 2))
        except ValueError:
            return text
