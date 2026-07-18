from methods.base import BaseMethod

class BCDMethod(BaseMethod):
    name = "BCD"
    description = "Binary Coded Decimal - each digit as 4-bit binary"
    category = "Other"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isdigit():
                result.append(format(int(ch), '04b'))
            else:
                result.append(ch)
        return ' '.join(result)
