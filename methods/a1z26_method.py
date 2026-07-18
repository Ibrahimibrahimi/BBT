from methods.base import BaseMethod


class A1Z26Method(BaseMethod):
    name = "A1Z26"
    description = "Letter-to-number cipher (A=1, B=2, ... Z=26), space-separated"
    category = "Cipher"

    def encode(self, text: str) -> str:
        parts = []
        for ch in text:
            if ch.isalpha():
                parts.append(str(ord(ch.upper()) - ord("A") + 1))
            elif ch == " ":
                parts.append("/")
            else:
                parts.append(ch)
        return " ".join(parts)
