from methods.base import BaseMethod

class QuinaryMethod(BaseMethod):
    name = "Quinary"
    description = "Convert to base-5"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num == 0:
            return "0"
        result = ""
        while num > 0:
            result = str(num % 5) + result
            num //= 5
        return result
