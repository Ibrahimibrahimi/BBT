from methods.base import BaseMethod


class GB2312Method(BaseMethod):
    name = "GB2312"
    description = "GB2312 encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        try:
            data = text.encode("gb2312")
        except (UnicodeEncodeError, UnicodeDecodeError):
            data = text.encode("utf-8")
        return " ".join(f"{b:02x}" for b in data)
