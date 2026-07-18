from methods.base import BaseMethod

class HexToDecMethod(BaseMethod):
    name = "Hex to Decimal"
    description = "Parse as hex, output decimal"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return str(int(text.strip(), 16))
        except ValueError:
            return text
