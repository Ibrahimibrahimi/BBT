from methods.base import BaseMethod


class EUCJPMethod(BaseMethod):
    name = "EUC-JP"
    description = "EUC-JP encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        try:
            data = text.encode("euc-jp")
        except (UnicodeEncodeError, UnicodeDecodeError):
            data = text.encode("utf-8")
        return " ".join(f"{b:02x}" for b in data)
