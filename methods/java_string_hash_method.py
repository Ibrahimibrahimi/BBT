from methods.base import BaseMethod


class JavaStringHashMethod(BaseMethod):
    name = "Java String Hash"
    description = "Java String.hashCode() implementation"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for ch in text:
            h = (31 * h + ord(ch)) & 0xFFFFFFFF
        if h >= 0x80000000:
            h -= 0x100000000
        return f"{h & 0xFFFFFFFF:08x}"
