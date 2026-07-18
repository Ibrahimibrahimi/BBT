from methods.base import BaseMethod

class AutokeyMethod(BaseMethod):
    name = "Autokey"
    description = "Polyalphabetic autokey cipher with keyword 'K'"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "K"
        key_stream = keyword.upper()
        for ch in text:
            if ch.isalpha():
                key_stream += ch.upper()

        result = ""
        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                k = ord(key_stream[ki]) - ord('A')
                result += chr((ord(ch.upper()) - ord('A') + k) % 26 + base)
                ki += 1
            else:
                result += ch
        return result
