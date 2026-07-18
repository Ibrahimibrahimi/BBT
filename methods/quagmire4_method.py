from methods.base import BaseMethod


class Quagmire4Method(BaseMethod):
    name = "Quagmire IV"
    description = "Quagmire IV: combined variant substitution cipher"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "QUAGMIRE"
        indicator = "D"
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

        ind = ord(indicator.upper()) - ord('A')
        shifted = cipher_alphabet[ind:] + cipher_alphabet[:ind]

        letters = [c.upper() for c in text if c.isalpha()]
        key_char = indicator.upper()
        result = []
        for ch in letters:
            rot = ord(key_char) - ord('A')
            sub = shifted[rot:] + shifted[:rot]
            sub_map = dict(zip(alphabet, sub))
            enc = sub_map.get(ch, ch)
            result.append(enc)
            key_char = enc

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
