from methods.base import BaseMethod


class VariantMethod(BaseMethod):
    name = "Variant"
    description = "Variant cipher: keyword-based substitution"
    category = "Cipher"

    def encode(self, text: str) -> str:
        keyword = "VARIANT"
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

        mapping = dict(zip(alphabet, cipher_alphabet))
        result = []
        for ch in text.upper():
            if ch in mapping:
                result.append(mapping[ch])
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
