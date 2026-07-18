from methods.base import BaseMethod


class SDBMMethod(BaseMethod):
    name = "SDBM"
    description = "SDBM hash function"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        for b in text.encode():
            h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
        return f"{h:08x}"
