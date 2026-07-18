from methods.base import BaseMethod


class LuhnMethod(BaseMethod):
    name = "Luhn"
    description = "Luhn, credit card check digit algorithm"
    category = "Hash"

    def encode(self, text: str) -> str:
        digits = [int(d) for d in text if d.isdigit()]
        if not digits:
            return "no digits"
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        total = sum(digits)
        check = (10 - (total % 10)) % 10
        return f"check_digit={check}"
