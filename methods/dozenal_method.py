from methods.base import BaseMethod

class DozenalMethod(BaseMethod):
    name = "Dozenal"
    description = "Convert to base-12 using 0-9 and X, E"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num == 0:
            return "0"
        digits = "0123456789XE"
        result = ""
        while num > 0:
            result = digits[num % 12] + result
            num //= 12
        return result
