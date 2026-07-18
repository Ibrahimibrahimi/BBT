from methods.base import BaseMethod


class VigenereMethod(BaseMethod):
    name = "Vigenere"
    description = 'Vigenere cipher using the fixed key "CRYPTER"'
    category = "Cipher"

    KEY = "CRYPTER"

    def encode(self, text: str) -> str:
        result = []
        key_index = 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                shift = ord(self.KEY[key_index % len(self.KEY)].upper()) - ord("A")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                key_index += 1
            else:
                result.append(ch)
        return "".join(result)
