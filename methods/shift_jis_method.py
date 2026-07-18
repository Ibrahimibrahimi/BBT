from methods.base import BaseMethod


class ShiftJISMethod(BaseMethod):
    name = "Shift_JIS"
    description = "Shift_JIS encoding"
    category = "Encoding"

    def encode(self, text: str) -> str:
        try:
            data = text.encode("shift_jis")
        except (UnicodeEncodeError, UnicodeDecodeError):
            data = text.encode("utf-8")
        return " ".join(f"{b:02x}" for b in data)
