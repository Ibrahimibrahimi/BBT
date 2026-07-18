from methods.base import BaseMethod

class OnesComplementMethod(BaseMethod):
    name = "1's Complement"
    description = "Convert to 8-bit 1's complement"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num < -127 or num > 127:
            return text
        if num < 0:
            num = (1 << 8) - 1 + num
        return format(num, '08b')
