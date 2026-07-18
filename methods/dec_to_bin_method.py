from methods.base import BaseMethod

class DecToBinMethod(BaseMethod):
    name = "Decimal to Binary"
    description = "Parse as int, output binary"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            return bin(int(text.strip()))[2:]
        except ValueError:
            return text
