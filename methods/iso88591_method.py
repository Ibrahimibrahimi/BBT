from methods.base import BaseMethod


class ISO88591Method(BaseMethod):
    name = "ISO-8859-1"
    description = "ISO-8859-1 (Latin-1) hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode("latin-1")
        return " ".join(f"{b:02x}" for b in data)
