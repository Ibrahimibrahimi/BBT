from methods.base import BaseMethod


class Caesar23Method(BaseMethod):
    name = "Caesar (+23)"
    description = "Classic Caesar cipher, shift of 23"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 23) % 26 + base)
            else:
                result += ch
        return result
