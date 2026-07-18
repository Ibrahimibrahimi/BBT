from methods.base import BaseMethod


class NicodemusMethod(BaseMethod):
    name = "Nicodemus"
    description = "Nicodemus cipher: Vigenere variant with plaintext feedback"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "NICODEMUS"
        clean = [c.upper() for c in text if c.isalpha()]
        key_upper = key.upper()

        result = []
        for i, ch in enumerate(clean):
            shift = ord(key_upper[i % len(key_upper)]) - ord('A')
            if i > 0:
                shift += ord(clean[i - 1]) - ord('A')
            result.append(chr((ord(ch) - ord('A') + shift % 26) % 26 + ord('A')))

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
