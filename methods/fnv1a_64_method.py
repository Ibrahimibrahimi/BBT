from methods.base import BaseMethod


class FNV1a64Method(BaseMethod):
    name = "FNV-1a 64"
    description = "FNV-1a non-cryptographic hash (64-bit)"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0xcbf29ce484222325
        for b in text.encode():
            h ^= b
            h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
        return f"{h:016x}"
