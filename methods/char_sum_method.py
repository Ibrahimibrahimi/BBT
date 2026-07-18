from methods.base import BaseMethod


class CharSumMethod(BaseMethod):
    name = "Char Sum"
    description = "Sum of all UTF-8 byte values, shown as a decimal checksum"
    category = "Custom"

    def encode(self, text: str) -> str:
        total = sum(text.encode("utf-8"))
        return str(total)
