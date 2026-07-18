from methods.base import BaseMethod

class BalancedTernaryMethod(BaseMethod):
    name = "Balanced Ternary"
    description = "Digits -1, 0, 1 (T, 0, 1)"
    category = "Other"

    def encode(self, text: str) -> str:
        try:
            num = int(text.strip())
        except ValueError:
            return text
        if num == 0:
            return "0"
        result = ""
        while num != 0:
            rem = num % 3
            if rem == 2:
                result = "T" + result
                num = num // 3 + 1
            elif rem == 1:
                result = "1" + result
                num = num // 3
            else:
                result = "0" + result
                num = num // 3
        return result
