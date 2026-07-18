from methods.base import BaseMethod

class Caesar20Method(BaseMethod):
    name = "Caesar (+20)"
    description = "Classic Caesar cipher, shift of 20"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 20) % 26 + base)
            else:
                result += ch
        return result
