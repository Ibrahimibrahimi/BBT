from methods.base import BaseMethod


class Windows1252Method(BaseMethod):
    name = "Windows-1252"
    description = "Windows-1252 hex encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        data = text.encode("cp1252")
        return " ".join(f"{b:02x}" for b in data)
