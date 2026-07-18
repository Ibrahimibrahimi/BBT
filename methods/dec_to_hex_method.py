from methods.base import BaseMethod

class DecToHexMethod(BaseMethod):
    name = "Decimal to Hex"
    description = "Parse as int, output hex"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return hex(int(text.strip()))[2:]
        except ValueError:
            return text
