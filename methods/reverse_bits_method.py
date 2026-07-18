from methods.base import BaseMethod


class ReverseBitsMethod(BaseMethod):
    name = "Reverse Bits"
    description = "Reverse Bits, reverse bits of each byte"
    category = "Other"

    def encode(self, text: str) -> str:
        data = text.encode()
        result = []
        for byte in data:
            rev = 0
            b = byte
            for _ in range(8):
                rev = (rev << 1) | (b & 1)
                b >>= 1
            result.append(rev)
        return " ".join(f"{b:02x}" for b in result)
