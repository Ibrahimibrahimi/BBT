from methods.base import BaseMethod

class SexagesimalMethod(BaseMethod):
    name = "Sexagesimal"
    description = "Convert to base-60 (Babylonian)"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num == 0:
            return "0"
        digits = "0123456789ABCDEFGHJKLMNPQRSTVWXYZ"
        result = ""
        while num > 0:
            result = digits[num % 60] + result
            num //= 60
        return result
