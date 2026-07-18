from methods.base import BaseMethod

class FactorialMethod(BaseMethod):
    name = "Factorial Number System"
    description = "Represent as factoradic"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num == 0:
            return "0"
        result = ""
        i = 1
        while num > 0:
            result = str(num % i) + result if result else str(num % i)
            num //= i
            i += 1
        return result
