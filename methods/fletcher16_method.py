from methods.base import BaseMethod


class Fletcher16Method(BaseMethod):
    name = "Fletcher16"
    description = "Fletcher16, 16-bit checksum"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        sum1 = 0
        sum2 = 0
        for byte in data:
            sum1 = (sum1 + byte) % 255
            sum2 = (sum2 + sum1) % 255
        return f"{(sum2 << 8) | sum1:04x}"
