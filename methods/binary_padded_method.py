from methods.base import BaseMethod


class BinaryPaddedMethod(BaseMethod):
    name = "Binary (padded)"
    description = "Zero-padded 8-bit binary with 0b prefix"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(f"0b{b:08b}" for b in text.encode("utf-8"))
