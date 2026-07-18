from methods.base import BaseMethod


class Caesar11Method(BaseMethod):
    name = "Caesar (+11)"
    description = "Classic Caesar cipher, shift of 11"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 11) % 26 + base)
            else:
                result += ch
        return result
