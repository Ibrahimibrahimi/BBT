from methods.base import BaseMethod


class Base20Method(BaseMethod):
    name = "Base20"
    description = "Base20 (Vigesimal) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        digits = "0123456789ABCDEFGHIJ"
        result = []
        for byte in text.encode("utf-8"):
            result.append(digits[byte // 20] + digits[byte % 20])
        return " ".join(result)
