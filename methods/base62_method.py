from methods.base import BaseMethod


class Base62Method(BaseMethod):
    name = "Base62"
    description = "Base62 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode("utf-8")
        num = int.from_bytes(data, "big")
        if num == 0:
            return "0"
        digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        result = []
        while num > 0:
            result.append(digits[num % 62])
            num //= 62
        return "".join(reversed(result))
