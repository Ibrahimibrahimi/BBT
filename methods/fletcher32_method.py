from methods.base import BaseMethod


class Fletcher32Method(BaseMethod):
    name = "Fletcher32"
    description = "Fletcher32, 32-bit checksum"
    category = "Hash"

    def encode(self, text: str) -> str:
        data = text.encode()
        sum1 = 0
        sum2 = 0
        for i in range(0, len(data), 2):
            word = data[i]
            if i + 1 < len(data):
                word = (data[i] << 8) | data[i + 1]
            sum1 = (sum1 + word) % 65535
            sum2 = (sum2 + sum1) % 65535
        return f"{(sum2 << 16) | sum1:08x}"
