from methods.base import BaseMethod


class PortaxMethod(BaseMethod):
    name = "Portax"
    description = "Portax cipher: variant of Porta with different tabular method"
    category = "Cipher"

    def encode(self, text: str) -> str:
        key = "PORTAX"
        alphabet = "ABCDEFGHIJKLMNO"

        def porta_shift(k, p):
            row = ord(k.upper()) - ord('A')
            if row > 13:
                row = 13
            if p.upper() < 'N':
                return (row + ord(p.upper()) - ord('A')) % 26
            else:
                return (row + ord(p.upper()) - ord('A') + 13) % 26

        letters = [c.upper() for c in text if c.isalpha()]
        key_idx = 0
        result = []
        for ch in letters:
            shift = porta_shift(key[key_idx % len(key)], ch)
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            key_idx += 1

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
