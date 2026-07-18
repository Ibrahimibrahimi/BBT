from methods.base import BaseMethod


class Base1Method(BaseMethod):
    name = "Base1"
    description = "Base1 (Unary) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        result = []
        for byte in text.encode("utf-8"):
            result.append("1" * byte + "0")
        return " ".join(result)
