from methods.base import BaseMethod


class Caesar9Method(BaseMethod):
    name = "Caesar (+9)"
    description = "Classic Caesar cipher, shift of 9"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 9) % 26 + base)
            else:
                result += ch
        return result
