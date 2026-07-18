from methods.base import BaseMethod


class Quagmire2Method(BaseMethod):
    name = "Quagmire II"
    description = "Quagmire II: keyword-based substitution with indicator key"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "QUAGMIRE"
        indicator_key = "B"
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

        ind = ord(indicator_key.upper()) - ord('A')
        shifted = cipher_alphabet[ind:] + cipher_alphabet[:ind]

        mapping = dict(zip(alphabet, shifted))
        letters = [c.upper() for c in text if c.isalpha()]
        result = []
        key_idx = 0
        for ch in letters:
            if ch in mapping:
                rot = (ord(indicator_key.upper()) - ord('A') + key_idx) % 26
                sub = shifted[rot:] + shifted[:rot]
                sub_map = dict(zip(alphabet, sub))
                result.append(sub_map.get(ch, ch))
                key_idx += 1
            else:
                result.append(ch)

        out = ""
        idx = 0
        for ch in text:
            if ch.isalpha():
                out += result[idx]
                idx += 1
            else:
                out += ch
        return out
