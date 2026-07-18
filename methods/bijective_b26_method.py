from methods.base import BaseMethod

class BijectiveB26Method(BaseMethod):
    name = "Bijective Base-26"
    description = "A=1, B=2, ..., Z=26, then 27=AA"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num <= 0:
            return text
        result = ""
        while num > 0:
            num -= 1
            result = chr(65 + num % 26) + result
            num //= 26
        return result
