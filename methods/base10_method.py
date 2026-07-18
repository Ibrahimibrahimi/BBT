from methods.base import BaseMethod


class Base10Method(BaseMethod):
    name = "Base10"
    description = "Base10 (Decimal) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(str(b) for b in text.encode("utf-8"))
