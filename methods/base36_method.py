from methods.base import BaseMethod


class Base36Method(BaseMethod):
    name = "Base36"
    description = "Base36 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode("utf-8")
        num = int.from_bytes(data, "big")
        if num == 0:
            return "0"
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        result = []
        while num > 0:
            result.append(digits[num % 36])
            num //= 36
        return "".join(reversed(result))
