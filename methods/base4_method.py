from methods.base import BaseMethod


class Base4Method(BaseMethod):
    name = "Base4"
    description = "Base4 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        result = []
        for byte in text.encode("utf-8"):
            high = byte >> 4
            low = byte & 0x0F
            result.append(f"{high}{low}")
        return " ".join(result)
