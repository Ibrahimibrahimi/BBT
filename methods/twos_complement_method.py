from methods.base import BaseMethod

class TwosComplementMethod(BaseMethod):
    name = "2's Complement"
    description = "Convert to 8-bit 2's complement"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num < -128 or num > 127:
            return text
        if num < 0:
            num = (1 << 8) + num
        return format(num, '08b')
