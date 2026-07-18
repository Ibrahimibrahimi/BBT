from methods.base import BaseMethod


class Base12Method(BaseMethod):
    name = "Base12"
    description = "Base12 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        digits = "0123456789AB"
        result = []
        for byte in text.encode("utf-8"):
            result.append(digits[byte // 12] + digits[byte % 12])
        return " ".join(result)
