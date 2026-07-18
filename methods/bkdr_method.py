from methods.base import BaseMethod


class BKDRMethod(BaseMethod):
    name = "BKDR"
    description = "BKDR hash function"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 0
        seed = 131
        for b in text.encode():
            h = (h * seed + b) & 0xFFFFFFFF
        return f"{h:08x}"
