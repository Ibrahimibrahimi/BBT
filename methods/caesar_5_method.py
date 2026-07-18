from methods.base import BaseMethod

class Caesar5Method(BaseMethod):
    name = "Caesar (+5)"
    description = "Classic Caesar cipher, shift of 5"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch) - base + 5) % 26 + base)
            else:
                result += ch
        return result
