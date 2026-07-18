from methods.base import BaseMethod


class OctalPaddedMethod(BaseMethod):
    name = "Octal (padded)"
    description = "Zero-padded 3-digit octal encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        return " ".join(f"{b:03o}" for b in text.encode("utf-8"))
