from methods.base import BaseMethod

class DecToOctMethod(BaseMethod):
    name = "Decimal to Octal"
    description = "Parse as int, output octal"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return oct(int(text.strip()))[2:]
        except ValueError:
            return text
