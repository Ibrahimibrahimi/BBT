from methods.base import BaseMethod

class GrayCodeMethod(BaseMethod):
    name = "Gray Code"
    description = "Convert to binary reflected Gray code"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text)
        except ValueError:
            return text
        gray = num ^ (num >> 1)
        return bin(gray)[2:]
