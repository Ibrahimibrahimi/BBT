from methods.base import BaseMethod


class XORSumMethod(BaseMethod):
    name = "XOR Sum"
    description = "XOR of all bytes as 2-char hex"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for b in text.encode():
            h ^= b
        return f"{h:02x}"
