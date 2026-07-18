from methods.base import BaseMethod

class GronsfeldMethod(BaseMethod):
    name = "Gronsfeld"
    description = "Numeric key Vigenere variant with key '31415'"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = [3, 1, 4, 1, 5]
        result = ""
        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                k = key[ki % len(key)]
                result += chr((ord(ch.upper()) - ord('A') + k) % 26 + base)
                ki += 1
            else:
                result += ch
        return result
