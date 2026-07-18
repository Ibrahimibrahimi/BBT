from methods.base import BaseMethod


class Caesar8Method(BaseMethod):
    name = "Caesar (+8)"
    description = "Classic Caesar cipher, shift of 8"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 8) % 26 + base)
            else:
                result += ch
        return result
