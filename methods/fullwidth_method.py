from methods.base import BaseMethod


class FullwidthMethod(BaseMethod):
    name = "Fullwidth"
    description = "Converts ASCII letters/digits to Unicode fullwidth forms (aesthetic text)"
    category = "Custom"

    def encode(self, text: str) -> str:
        result = []
        for ch in text:
            code = ord(ch)
            if 0x21 <= code <= 0x7E:
                result.append(chr(code - 0x21 + 0xFF01))
            elif ch == " ":
                result.append("\u3000")
            else:
                result.append(ch)
        return "".join(result)
