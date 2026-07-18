from methods.base import BaseMethod

class Excess3Method(BaseMethod):
    name = "Excess-3"
    description = "Each digit + 3 as 4-bit binary"
    category = "Other"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            if ch.isdigit():
                result.append(format(int(ch) + 3, '04b'))
            else:
                result.append(ch)
        return ' '.join(result)
