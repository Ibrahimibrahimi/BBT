from methods.base import BaseMethod

class BeaufortMethod(BaseMethod):
    name = "Beaufort"
    description = "Reciprocal Vigenere cipher with keyword 'KEY'"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "KEY"
        result = ""
        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                k = ord(keyword[ki % len(keyword)]) - ord('A')
                result += chr((k - (ord(ch.upper()) - ord('A'))) % 26 + base)
                ki += 1
            else:
                result += ch
        return result
