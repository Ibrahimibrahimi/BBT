from methods.base import BaseMethod


class APMethod(BaseMethod):
    name = "AP"
    description = "AP hash function"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for i, b in enumerate(text.encode()):
            if i & 1:
                h ^= (h << 7) ^ b ^ (h >> 3)
            else:
                h ^= ~(h << 11) ^ b ^ (h >> 5)
        return f"{h & 0xFFFFFFFF:08x}"
