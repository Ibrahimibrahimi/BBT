from methods.base import BaseMethod

class TrithemiusMethod(BaseMethod):
    name = "Trithemius"
    description = "Shifting alphabet cipher, each letter shifted by its position"
    category = "Cipher"

    def encode(self, text: str) -> str:
        result = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result += chr((ord(ch.upper()) - ord('A') + idx) % 26 + base)
                idx += 1
            else:
                result += ch
        return result
