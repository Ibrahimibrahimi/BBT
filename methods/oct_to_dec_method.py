from methods.base import BaseMethod

class OctToDecMethod(BaseMethod):
    name = "Octal to Decimal"
    description = "Parse as octal, output decimal"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return str(int(text.strip(), 8))
        except ValueError:
            return text
