from methods.base import BaseMethod


class Base2Method(BaseMethod):
    name = "Base2"
    description = "Base2 (Binary 0/1) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(format(b, "08b") for b in text.encode("utf-8"))
