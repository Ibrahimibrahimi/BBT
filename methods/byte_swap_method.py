from methods.base import BaseMethod


class ByteSwapMethod(BaseMethod):
    name = "Byte Swap"
    description = "Byte Swap, swap adjacent byte pairs"
    category = "Other"

    def encode(self, text: str) -> str:
        data = text.encode()
        result = bytearray(data)
        for i in range(0, len(result) - 1, 2):
            result[i], result[i + 1] = result[i + 1], result[i]
        return " ".join(f"{b:02x}" for b in result)
