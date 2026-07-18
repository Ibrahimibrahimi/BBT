from methods.base import BaseMethod


class SCSUMethod(BaseMethod):
    name = "SCSU"
    description = "SCSU (simplified) encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(str(ord(c)) for c in text)
