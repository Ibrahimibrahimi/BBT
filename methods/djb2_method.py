from methods.base import BaseMethod


class DJB2Method(BaseMethod):
    name = "DJB2"
    description = "Dan Bernstein's DJB2 hash"
    category = "Hash"

    def encode(self, text: str) -> str:
        h = 5381
        for b in text.encode():
            h = ((h << 5) + h + b) & 0xFFFFFFFF
        return f"{h:08x}"
