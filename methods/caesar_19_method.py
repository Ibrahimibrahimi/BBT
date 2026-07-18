from methods.base import BaseMethod


class Caesar19Method(BaseMethod):
    name = "Caesar (+19)"
    description = "Classic Caesar cipher, shift of 19"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 19) % 26 + base)
            else:
                result += ch
        return result
