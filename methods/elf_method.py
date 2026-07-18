from methods.base import BaseMethod


class ELFMethod(BaseMethod):
    name = "ELF"
    description = "ELF/PJW hash function"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for b in text.encode():
            h = ((h << 4) + b) & 0xFFFFFFFF
            g = h & 0xF0000000
            if g:
                h ^= g >> 24
            h &= ~g
        return f"{h:08x}"
