from methods.base import BaseMethod


class Quagmire1Method(BaseMethod):
    name = "Quagmire I"
    description = "Quagmire I: simple substitution with keyword indicator"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "QUAGMIRE"
        indicator = "A"
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        cipher_alphabet = ""
        used = set()
        for ch in keyword.upper():
            if ch not in used and ch in alphabet:
                used.add(ch)
                cipher_alphabet += ch
        for ch in alphabet:
            if ch not in used:
                cipher_alphabet += ch

        shift = ord(indicator.upper()) - ord('A')
        shifted = cipher_alphabet[shift:] + cipher_alphabet[:shift]

        mapping = dict(zip(alphabet, shifted))
        letters = [c.upper() for c in text if c.isalpha()]
        result = [mapping.get(ch, ch) for ch in letters]

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
