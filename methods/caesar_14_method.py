from methods.base import BaseMethod


class Caesar14Method(BaseMethod):
    name = "Caesar (+14)"
    description = "Classic Caesar cipher, shift of 14"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 14) % 26 + base)
            else:
                result += ch
        return result
