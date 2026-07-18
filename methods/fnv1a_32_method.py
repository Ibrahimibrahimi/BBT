from methods.base import BaseMethod


class FNV1a32Method(BaseMethod):
    name = "FNV-1a 32"
    description = "FNV-1a non-cryptographic hash (32-bit)"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0x811c9dc5
        for b in text.encode():
            h ^= b
            h = (h * 0x01000193) & 0xFFFFFFFF
        return f"{h:08x}"
